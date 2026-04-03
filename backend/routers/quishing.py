"""
Quishing (QR Code Phishing) Detection — decode QR from image, analyze embedded URL.
Handles the fastest-growing phishing vector in 2025/2026.
"""
import io
import base64
import logging
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/quishing", tags=["quishing"])


def _decode_qr_from_bytes(image_bytes: bytes) -> str | None:
    """Decode QR code from image bytes using pyzbar + Pillow."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as pyzbar_decode
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        decoded = pyzbar_decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")
        return None
    except ImportError:
        logger.warning("[Quishing] pyzbar or Pillow not installed. Attempting fallback.")
        return None
    except Exception as e:
        logger.warning(f"[Quishing] QR decode failed: {e}")
        return None


def _decode_qr_fallback(image_bytes: bytes) -> str | None:
    """Fallback QR decode using opencv-python if pyzbar unavailable."""
    try:
        import cv2
        import numpy as np
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)
        return data if data else None
    except Exception:
        return None


@router.post("/decode")
async def decode_qr(file: UploadFile = File(...)):
    """Upload image containing QR code → decode → full phishing analysis of embedded URL."""
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Please upload an image file (PNG, JPG, WEBP, GIF).")

    image_bytes = await file.read()
    if len(image_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="Image too large. Maximum 10MB.")

    # Attempt QR decode
    decoded_url = _decode_qr_from_bytes(image_bytes)
    if not decoded_url:
        decoded_url = _decode_qr_fallback(image_bytes)

    if not decoded_url:
        raise HTTPException(
            status_code=422,
            detail="No QR code detected in this image. Ensure the QR code is clearly visible and well-lit.",
        )

    logger.info(f"[Quishing] Decoded QR URL: {decoded_url[:80]}")

    # Validate it's a URL
    is_url = decoded_url.startswith("http") or decoded_url.startswith("www.")
    if not is_url:
        return {
            "qr_decoded": True,
            "decoded_content": decoded_url,
            "is_url": False,
            "message": "QR code contains non-URL content. Not a phishing vector.",
        }

    url = decoded_url if decoded_url.startswith("http") else "https://" + decoded_url

    # Run full phishing analysis
    try:
        from routers.analyze import _run_full_analysis
        result = await _run_full_analysis(url, "url")
        return {
            "qr_decoded": True,
            "decoded_url": url,
            "is_url": True,
            "attack_type": "Quishing (QR Code Phishing)",
            "analysis": result,
        }
    except Exception as e:
        logger.error(f"[Quishing] Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


class Base64QRRequest(BaseModel):
    image_base64: str
    filename: str = "qr.png"


@router.post("/decode-base64")
async def decode_qr_base64(req: Base64QRRequest):
    """Decode QR code from base64-encoded image (for browser canvas/webcam capture)."""
    try:
        # Strip data URL prefix if present
        b64 = req.image_base64
        if "," in b64:
            b64 = b64.split(",", 1)[1]
        image_bytes = base64.b64decode(b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 image data.")

    decoded_url = _decode_qr_from_bytes(image_bytes) or _decode_qr_fallback(image_bytes)
    if not decoded_url:
        raise HTTPException(status_code=422, detail="No QR code detected.")

    url = decoded_url if decoded_url.startswith("http") else "https://" + decoded_url
    from routers.analyze import _run_full_analysis
    result = await _run_full_analysis(url, "url")
    return {"decoded_url": url, "attack_type": "Quishing", "analysis": result}
