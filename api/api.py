import hashlib
import os
import random
import shutil
import string
import threading
import time
from contextlib import asynccontextmanager
from os.path import basename
from pathlib import Path
from typing import Tuple

from db_setup import LogFile, LogSection, database, init_db, metadata
from fastapi import (
    BackgroundTasks,
    Body,
    FastAPI,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from natural_language import (
    batch_csv_to_nl_async,
    get_embedding,
    timeframe_csv_to_nl,
    timeframe_csv_to_nl_async,
    validate_csv_headers,
)
from sqlalchemy import update
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await database.connect()
    yield

    await database.disconnect()


app = FastAPI(title="Network Analyzer API", version="0.1.0", lifespan=lifespan)

# Configure CORS to dynamically allow the request origin
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex="https?://localhost(:[0-9]+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
)

# Configuration for file storage
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Simple in-memory session token store (dev only)
_EXEMPT_PATHS = {"/health", "/users/login"}
_valid_tokens = set()
_token_lock = threading.Lock()

PROCESSING_RULES = {
    "method": "batch",
    "timeframe_seconds": 10 * 60,
    "batch_size": 5,
}


class SessionCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _EXEMPT_PATHS:
            return await call_next(request)

        token = request.cookies.get("session_token")
        with _token_lock:
            if token in _valid_tokens:
                return await call_next(request)

        return JSONResponse({"detail": "Not authenticated"}, status_code=401)


app.add_middleware(SessionCookieMiddleware)

DATABASE_URL = os.environ.get("DATABASE_URL")
OPENROUTER_KEY = os.environ.get("OPENROUTER_KEY")
APP_PASSWORD = os.environ.get("APP_PASSWORD")
APP_PASSWORD = "test_password" if APP_PASSWORD is None else APP_PASSWORD


@app.post("/users/login")
def login(response: Response, password_hash: str = Body(...)):
    # Ensure the APP_PASSWORD environment variable is set
    if not APP_PASSWORD:
        raise HTTPException(status_code=500, detail="Server configuration error")

    # Hash the APP_PASSWORD to compare with the incoming hash
    expected_hash = hashlib.sha256(APP_PASSWORD.encode()).hexdigest()

    # Compare the provided hash against the hashed APP_PASSWORD
    if password_hash != expected_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate a random 32-character alphanumeric sequence
    random_seq = "".join(random.choices(string.ascii_letters + string.digits, k=32))

    # Store token for validation and set cookie
    with _token_lock:
        _valid_tokens.add(random_seq)

    # Set the cookie with the random sequence
    response.set_cookie(
        key="session_token",
        value=random_seq,
        httponly=True,
        secure=False,
        samesite="lax",
    )

    return {"status": "logged in"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/logs/list")
def list_files():

    try:
        if not UPLOAD_DIR.exists():
            raise FileNotFoundError("Log dir not found")

        # for every file in upload dir, if it is a file, add the filename
        filenames = [p.name for p in UPLOAD_DIR.iterdir() if p.is_file()]
        return {"files": filenames}

    except Exception as e:
        print(f"/logs/list ERR: {e}")
        raise HTTPException(status_code=500, detail="Internal Error")


async def on_section_nl_gen(log_file_uuid: int, data: Tuple[str, Tuple[int, int]]):
    emb = get_embedding(data[0])
    query = LogSection.__table__.insert().values(
        file_id=log_file_uuid,
        embedding=emb,
        start_packet_number=data[1][0],
        end_packet_number=data[1][1],
    )
    await database.execute(query)


async def process_log_upload(log_file_uuid: int, file_path: str):
    async def callback(data):
        await on_section_nl_gen(log_file_uuid, data)

    if PROCESSING_RULES["method"] == "timeframe":
        await timeframe_csv_to_nl_async(
            file_path,
            PROCESSING_RULES["timeframe_seconds"],
            callback,
        )
    elif PROCESSING_RULES["method"] == "batch":
        await batch_csv_to_nl_async(file_path, PROCESSING_RULES["batch_size"], callback)
    else:
        return

    # update(LogFile).where(LogFile.id == log_file_uuid).values(processed=True)
    query = (
        LogFile.__table__.update()
        .where(LogFile.id == log_file_uuid)
        .values(processed=True)
    )
    await database.execute(query)
    print("Log Uploaded")


# LOG endpoints
@app.post("/logs/upload")
async def upload_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    try:
        if file.filename is None:
            raise Exception("Error finding the filename")

        # grab uploaded filename, create unique filename from that and then locally save the file
        filename = basename(file.filename)
        unique_filename = f"{int(threading.get_ident())}_{int(time.time())}_{filename}"
        file_path = UPLOAD_DIR / unique_filename
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # if csv follows required scheme,
        # insert row into log_files,
        # start file processing and send success response
        if validate_csv_headers(str(file_path)):
            query = LogFile.__table__.insert().values(filename=unique_filename)
            id = await database.execute(query)
            background_tasks.add_task(process_log_upload, id, str(file_path))
            return {"id": id, "status": "saved"}
        else:
            raise HTTPException(
                status_code=422, detail="Incorrect csv formatting provided"
            )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save file: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
