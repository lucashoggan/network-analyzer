import asyncio
import hashlib
import os
import random
import string
import threading
import time
from contextlib import asynccontextmanager
from os.path import basename
from pathlib import Path
from typing import Tuple

import numpy as np
from sklearn.manifold import TSNE
from sklearn.neighbors import LocalOutlierFactor

from db_setup import LogFile, LogSection, database, init_db, metadata
from fastapi import (
    BackgroundTasks,
    Body,
    FastAPI,
    File,
    Form,
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

VALID_PROCESSING_METHODS = {"batch", "timeframe"}
EMBEDDING_BATCH_SIZE = 50


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
SKIP_EMBEDDINGS = os.environ.get("SKIP_EMBEDDINGS", "false").lower() == "true"


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
async def list_files():
    try:
        query = LogFile.__table__.select()
        rows = await database.fetch_all(query)
        return {"files": [
            {
                "id": row["id"],
                "filename": row["filename"],
                "processed": row["processed"],
                "processing_method": row["processing_method"],
                "processing_value": row["processing_value"],
                "uploaded_at": row["uploaded_at"].isoformat() if row["uploaded_at"] else None,
            }
            for row in rows
        ]}
    except Exception as e:
        print(f"/logs/list ERR: {e}")
        raise HTTPException(status_code=500, detail="Internal Error")


async def process_log_upload(log_file_uuid: int, file_path: str, processing_method: str, processing_value: int):
    if not SKIP_EMBEDDINGS:
        loop = asyncio.get_event_loop()
        pending: list[Tuple[str, Tuple[int, int]]] = []

        async def flush():
            if not pending:
                return
            embeddings = await asyncio.gather(
                *[loop.run_in_executor(None, get_embedding, s[0]) for s in pending]
            )
            await database.execute_many(
                LogSection.__table__.insert(),
                [
                    {
                        "file_id": log_file_uuid,
                        "embedding": emb,
                        "start_packet_number": s[1][0],
                        "end_packet_number": s[1][1],
                    }
                    for s, emb in zip(pending, embeddings)
                ],
            )
            pending.clear()

        async def callback(data):
            pending.append(data)
            if len(pending) >= EMBEDDING_BATCH_SIZE:
                await flush()

        if processing_method == "timeframe":
            await timeframe_csv_to_nl_async(file_path, processing_value, callback)
        elif processing_method == "batch":
            await batch_csv_to_nl_async(file_path, processing_value, callback)
        else:
            return

        await flush()  # flush any remaining sections

    query = (
        LogFile.__table__.update()
        .where(LogFile.id == log_file_uuid)
        .values(processed=True)
    )
    await database.execute(query)
    print("Log Uploaded")


# LOG endpoints
@app.post("/logs/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    processing_method: str = Form(...),
    processing_value: int = Form(...),
):
    if processing_method not in VALID_PROCESSING_METHODS:
        raise HTTPException(status_code=422, detail=f"processing_method must be one of {VALID_PROCESSING_METHODS}")
    if processing_value < 1:
        raise HTTPException(status_code=422, detail="processing_value must be at least 1")

    try:
        if file.filename is None:
            raise Exception("Error finding the filename")

        # grab uploaded filename, create unique filename from that and then locally save the file
        filename = basename(file.filename)
        unique_filename = f"{int(threading.get_ident())}_{int(time.time())}_{filename}"
        file_path = UPLOAD_DIR / unique_filename
        with file_path.open("wb") as buffer:
            while chunk := await file.read(8 * 1024 * 1024):  # 8 MB chunks
                buffer.write(chunk)

        # if csv follows required scheme,
        # insert row into log_files,
        # start file processing and send success response
        if validate_csv_headers(str(file_path)):
            query = LogFile.__table__.insert().values(
                filename=unique_filename,
                processing_method=processing_method,
                processing_value=processing_value,
            )
            id = await database.execute(query)
            background_tasks.add_task(process_log_upload, id, str(file_path), processing_method, processing_value)
            return {"id": id, "status": "saved"}
        else:
            raise HTTPException(
                status_code=422, detail="Incorrect csv formatting provided"
            )
    except HTTPException as e:
        raise e
    except Exception as e:
        import traceback
        print(f"/logs/upload ERR: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Could not save file: {str(e)}")


@app.get("/logs/{log_id}/map")
async def get_log_map(log_id: int):
    try:
        query = (
            LogSection.__table__
            .select()
            .where(LogSection.file_id == log_id)
        )
        rows = await database.fetch_all(query)

        if not rows:
            return {"points": []}

        def parse_embedding(raw) -> list[float]:
            if isinstance(raw, str):
                return [float(x) for x in raw.strip("[]").split(",")]
            return list(raw)

        embeddings = [parse_embedding(row["embedding"]) for row in rows]
        meta = [(row["start_packet_number"], row["end_packet_number"]) for row in rows]

        if len(embeddings) == 1:
            return {"points": [{"x": 0.0, "y": 0.0, "outlier_score": 0.0,
                                "start_packet_number": meta[0][0],
                                "end_packet_number": meta[0][1]}]}

        def run_analysis():
            n = len(embeddings)
            arr = np.array(embeddings, dtype=np.float32)

            # t-SNE: reduce to 2D for visualisation
            perplexity = min(30, max(2, n - 1))
            coords = TSNE(n_components=2, perplexity=perplexity, random_state=42).fit_transform(arr)
            mn, mx = coords.min(axis=0), coords.max(axis=0)
            rng = np.where(mx - mn == 0, 1, mx - mn)
            norm_coords = ((coords - mn) / rng).tolist()

            # LOF: computed on the full 1536-dim embeddings so spatial clusters
            # of unusual traffic are still detected as outliers vs the main population.
            # n_neighbors capped at n-1 to handle small datasets.
            n_neighbors = min(20, max(2, n - 1))
            lof = LocalOutlierFactor(n_neighbors=n_neighbors)
            lof.fit_predict(arr)
            # negative_outlier_factor_: -1 = perfect inlier, more negative = more outlier.
            # Negate so higher values mean more anomalous.
            raw_scores = -lof.negative_outlier_factor_
            s_min, s_max = raw_scores.min(), raw_scores.max()
            if s_max > s_min:
                norm_scores = ((raw_scores - s_min) / (s_max - s_min)).tolist()
            else:
                norm_scores = [0.0] * n

            return norm_coords, norm_scores

        loop = asyncio.get_event_loop()
        coords, scores = await loop.run_in_executor(None, run_analysis)

        return {"points": [
            {"x": c[0], "y": c[1], "outlier_score": s,
             "start_packet_number": m[0], "end_packet_number": m[1]}
            for c, s, m in zip(coords, scores, meta)
        ]}
    except Exception as e:
        print(f"/logs/{log_id}/map ERR: {e}")
        raise HTTPException(status_code=500, detail="Internal Error")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
