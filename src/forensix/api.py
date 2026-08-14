from fastapi import FastAPI

app = FastAPI(title="ForensiX API")


@app.get("/health")
def health():
    return {"status": "ok"}
