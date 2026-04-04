import hashlib
import os
import random
import string

from fastapi import Body, FastAPI, File, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Network Analyzer API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8080",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")
OPENAPI_KEY = os.environ.get("OPENAPI_KEY")
APP_PASSWORD = os.environ.get("APP_PASSWORD")
APP_PASSWORD = "test_password" if APP_PASSWORD is None else APP_PASSWORD


@app.post("/user/login")
def login(response: Response, password_hash: str = Body(...)):
    # Ensure the APP_PASSWORD environment variable is set
    if not APP_PASSWORD:
        raise HTTPException(status_code=500, detail="Server configuration error")

    # Hash the APP_PASSWORD to compare with the incoming hash
    expected_hash = hashlib.sha256(APP_PASSWORD.encode()).hexdigest()

    # Compare the provided hash against the hashed APP_PASSWORD
    if password_hash != expected_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate a random 10-character alphanumeric sequence
    random_seq = "".join(random.choices(string.ascii_letters + string.digits, k=32))

    # Set the cookie with the random sequence
    response.set_cookie(
        key="session_token",
        value=random_seq,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
    )

    return {"status": "logged in"}


@app.get("/health")
def health():
    print(APP_PASSWORD)
    return {"status": "healthy"}


@app.post("/uploadlog")
async def upload_file(file: UploadFile = File(...)):
    return {"filename": file.filename}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
