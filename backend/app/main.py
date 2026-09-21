from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import events, incidents, devices, protected_files, archives, containment
from .services.firebase_service import db_service

app = FastAPI(
    title="Ransomware Detection and Prevention API",
    description="Academic Backend API for Windows Ransomware Detection & Containment",
    version="1.0.0"
)

# Allow cross-origin requests from web dashboard and endpoint agents
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(devices.router)
app.include_router(protected_files.router)
app.include_router(archives.router)
app.include_router(containment.router)

@app.get("/")
def root():
    return {
        "system": "Ransomware Detection and Prevention System",
        "status": "ONLINE",
        "version": "1.0.0",
        "docs_url": "/docs",
        "devices_monitored": len(db_service.devices)
    }

@app.get("/api/logs")
def get_audit_logs():
    return db_service.audit_logs

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
