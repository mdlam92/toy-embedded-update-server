# Embedded Linux Update Server

A simple HTTP server that accepts signed firmware updates for an embedded Linux device.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Generate signing key and add to trust store
python tools/create_update.py genkey -o tools/signing_key
cp tools/signing_key.pub trust_store/

# Run server
python update_server.py
```

## Test

```bash
# Create and send an update
python tools/create_update.py create -k tools/signing_key.pem -o test_packages/test

curl -X POST http://localhost:8080/update \
     -H "X-Signature: $(cat test_packages/test.tar.gz.sig.b64)" \
     --data-binary @test_packages/test.tar.gz
```

## Update Format

Gzipped tarball containing `bootloader.bin`, `kernel.img`, `rootfs.squashfs`.

Detached Ed25519 signature in `X-Signature` header (base64).

## Your Task

Review `update_server.py`. What security issues do you see?
