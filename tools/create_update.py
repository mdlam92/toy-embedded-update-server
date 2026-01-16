#!/usr/bin/env python3
"""Create signed update packages."""

import argparse
import base64
import os
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def genkey(output: str):
    """Generate Ed25519 keypair."""
    key = Ed25519PrivateKey.generate()
    
    Path(f"{output}.pem").write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    Path(f"{output}.pub").write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    print(f"Created {output}.pem and {output}.pub")


def create(key_path: str, output: str):
    """Create a signed update package."""
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        
        # Create dummy images
        for name, size in [("bootloader.bin", 256), ("kernel.img", 1024), ("rootfs.squashfs", 4096)]:
            content = f"{name}\n".encode() + os.urandom(size)
            (tmp / name).write_bytes(content)
        
        # Create tarball
        tarball = Path(f"{output}.tar.gz")
        with tarfile.open(tarball, "w:gz") as tar:
            for f in tmp.iterdir():
                tar.add(f, arcname=f.name)
        
        # Sign
        sig = key.sign(tarball.read_bytes())
        Path(f"{output}.tar.gz.sig").write_bytes(sig)
        Path(f"{output}.tar.gz.sig.b64").write_text(base64.b64encode(sig).decode())
        
        print(f"Created {output}.tar.gz")
        print(f"Test: curl -X POST http://localhost:8080/update -H \"X-Signature: $(cat {output}.tar.gz.sig.b64)\" --data-binary @{output}.tar.gz")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    
    g = sub.add_parser("genkey")
    g.add_argument("-o", "--output", required=True)
    
    c = sub.add_parser("create")
    c.add_argument("-k", "--key", required=True)
    c.add_argument("-o", "--output", required=True)
    
    args = p.parse_args()
    if args.cmd == "genkey":
        genkey(args.output)
    else:
        create(args.key, args.output)
