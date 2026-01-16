#!/usr/bin/env python3
"""
Embedded Linux Update Server
Accepts signed firmware updates and installs them to device partitions.
Systemd starts this service on boot.
"""

import shutil
import tarfile
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import base64

app = FastAPI()

DEVICE_DIR = Path("./device")
TRUST_STORE = Path("./trust_store")

PARTITION_MAP = {
    "bootloader.bin": "mmcblk0p1",
    "kernel.img": "mmcblk0p2", 
    "rootfs.squashfs": "mmcblk0p3",
}


def load_trusted_keys() -> list[Ed25519PublicKey]:
    """Load all public keys from trust store."""
    keys = []
    for key_file in TRUST_STORE.glob("*.pub"):
        with open(key_file, "rb") as f:
            key_data = f.read()
            if b"BEGIN PUBLIC KEY" in key_data:
                key = serialization.load_pem_public_key(key_data)
            else:
                key = Ed25519PublicKey.from_public_bytes(key_data)
            keys.append(key)
    return keys


def verify_signature(data: bytes, signature: bytes, trusted_keys: list) -> bool:
    """Verify data was signed by a trusted key."""
    for key in trusted_keys:
        try:
            key.verify(signature, data)
            return True
        except InvalidSignature:
            continue
    return False


def extract_update(tarball_path: Path, extract_dir: Path) -> None:
    """Extract update tarball."""
    with tarfile.open(tarball_path, "r:gz") as tar:
        tar.extractall(extract_dir)


def install_images(extract_dir: Path) -> None:
    """Install images to partitions."""
    for image_name, partition in PARTITION_MAP.items():
        image_path = extract_dir / image_name
        target_path = DEVICE_DIR / partition
        
        if not image_path.exists():
            raise FileNotFoundError(f"Missing image: {image_name}")
        
        shutil.copy(image_path, target_path)
        print(f"Installed {image_name} -> {partition}")


@app.get("/status")
def status():
    return {"status": "running"}


@app.post("/update")
async def update(request: Request, x_signature: str = Header()):
    """
    Install a firmware update.
    Body: raw .tar.gz update package
    X-Signature header: base64-encoded Ed25519 signature
    """
    update_data = await request.body()
    
    try:
        signature = base64.b64decode(x_signature)
    except Exception:
        raise HTTPException(400, "Invalid signature encoding")
    
    trusted_keys = load_trusted_keys()
    if not trusted_keys:
        raise HTTPException(500, "No trusted keys configured")
    
    if not verify_signature(update_data, signature, trusted_keys):
        raise HTTPException(401, "Invalid signature")
    
    # Extract and install
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        tarball_path = tmp_path / "update.tar.gz"
        tarball_path.write_bytes(update_data)
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        extract_update(tarball_path, extract_dir)
        
        try:
            install_images(extract_dir)
        except FileNotFoundError as e:
            raise HTTPException(400, str(e))
    
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    DEVICE_DIR.mkdir(exist_ok=True)
    for partition in PARTITION_MAP.values():
        p = DEVICE_DIR / partition
        if not p.exists():
            p.write_bytes(b"\x00" * 1024)
    uvicorn.run(app, host="0.0.0.0", port=8080)
