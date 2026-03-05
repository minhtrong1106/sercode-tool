from flask import Flask, request, jsonify, send_file
import os
import time
import threading
import requests
from dotenv import load_dotenv
import numpy as np
import cv2
from urllib.parse import urlparse

load_dotenv()

APP = Flask(__name__)
APP.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB

@APP.get("/")
def home():
    return send_file("index.html")

@APP.get("/healthz")
def healthz():
    return "ok", 200


GET_TOKEN_URL = "https://trace-open-api.motul.com.sg/cncop/ca/v1/applications/get-token"
CODE_QUERY_URL = "https://trace-open-api.motul.com.sg/customer/mote/open/api/v1/codeQuery"

ACCESS_KEY = os.getenv("ACCESS_KEY", "").strip()
SECRET_KEY_SIGN = os.getenv("SECRET_KEY_SIGN", "").strip()

# Token cache + lock chống race (nhiều request cùng lúc)
_token_cache = {"token": None, "expire_at": 0.0}
_token_lock = threading.Lock()


def _extract_access_token(data: dict) -> str | None:
    """
    Lấy token từ các format response thường gặp.
    (Bạn có thể chỉnh thêm nếu response thực tế khác)
    """
    if not isinstance(data, dict):
        return None

    # {"accessToken": "..."}
    v = data.get("accessToken")
    if isinstance(v, str) and v.strip():
        return v.strip()

    d = data.get("data")

    # {"data": {"accessToken": "..."}}
    if isinstance(d, dict):
        v = d.get("accessToken")
        if isinstance(v, str) and v.strip():
            return v.strip()

        # {"data": {"token": "..."}}
        v = d.get("token")
        if isinstance(v, str) and v.strip():
            return v.strip()

    # {"token": "..."}
    v = data.get("token")
    if isinstance(v, str) and v.strip():
        return v.strip()

    # {"data": "..."} (string)
    if isinstance(d, str) and d.strip():
        return d.strip()

    return None


def _get_expires_in(data: dict) -> int:
    """
    Lấy expiresIn (nếu có), fallback 600s.
    """
    expires_in = None
    if isinstance(data, dict):
        expires_in = data.get("expiresIn") or data.get("expireIn")
        if expires_in is None and isinstance(data.get("data"), dict):
            expires_in = data["data"].get("expiresIn") or data["data"].get("expireIn")

    try:
        return int(expires_in) if expires_in is not None else 600
    except Exception:
        return 600


def _invalidate_token_cache():
    with _token_lock:
        _token_cache["token"] = None
        _token_cache["expire_at"] = 0.0


def _get_token(force_refresh: bool = False) -> str:
    """
    Lấy token có cache.
    force_refresh=True sẽ bỏ cache và gọi get-token lại.
    """
    if not ACCESS_KEY or not SECRET_KEY_SIGN:
        raise RuntimeError("Thiếu ACCESS_KEY hoặc SECRET_KEY_SIGN trong env")

    now = time.time()
    if (not force_refresh) and _token_cache["token"] and now < _token_cache["expire_at"]:
        return _token_cache["token"]

    with _token_lock:
        # double-check sau khi acquire lock
        now = time.time()
        if (not force_refresh) and _token_cache["token"] and now < _token_cache["expire_at"]:
            return _token_cache["token"]

        resp = requests.post(
            GET_TOKEN_URL,
            json={"accessKey": ACCESS_KEY, "secretKeySign": SECRET_KEY_SIGN},
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()

        token = _extract_access_token(data)
        if not token:
            raise RuntimeError(f"Không tìm thấy token trong response: {data}")

        token = token.strip()
        expires_in = _get_expires_in(data)

        # trừ hao 30s
        _token_cache["token"] = token
        _token_cache["expire_at"] = time.time() + max(60, expires_in - 30)
        return token


def normalize_search_code(s: str) -> str:
    """
    Nếu QR trả URL dạng https://st4.ch/q/XXXX -> lấy XXXX
    Nếu đã là code thì giữ nguyên.
    """
    s = (s or "").strip()
    if not s:
        return s

    low = s.lower()
    if low.startswith("http://") or low.startswith("https://"):
        u = urlparse(s)
        parts = [p for p in u.path.split("/") if p]
        for i, part in enumerate(parts):
            if part.lower() == "q" and i + 1 < len(parts):
                return parts[i + 1].strip()
        return (parts[-1].strip() if parts else s)

    return s


def _is_invalid_token_payload(j) -> bool:
    """
    Gateway có thể trả HTTP 200 nhưng body báo invalid token (meta.status=401).
    """
    if not isinstance(j, dict):
        return False

    meta = j.get("meta")
    if isinstance(meta, dict) and meta.get("status") == 401:
        return True

    if j.get("status") == 401:
        return True

    msg = j.get("message") if isinstance(j.get("message"), str) else ""
    reason = ""
    if isinstance(j.get("data"), dict) and isinstance(j["data"].get("reason"), str):
        reason = j["data"]["reason"]

    text = f"{msg} {reason}".lower()
    return "invalid token" in text or "reauthentication" in text


def _call_code_query(token: str, search_code: str, query_type: int):
    """
    Gọi API codeQuery.
    Trả (http_status, json_or_none, raw_text).
    """
    resp = requests.post(
        CODE_QUERY_URL,
        headers={
            "Authorization": token,           # ✅ đúng như Postman
            "accessKey": ACCESS_KEY,          # ✅ rất hay là header bắt buộc (Postman có thể gửi context khác)
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "PostmanRuntime/7.39.0"  # ✅ optional nhưng hữu ích với gateway khó tính
        },
        json={"searchCode": search_code, "queryType": query_type},
        timeout=25
    )

    try:
        j = resp.json()
        return resp.status_code, j, resp.text
    except Exception:
        return resp.status_code, None, resp.text


@APP.get("/api/debug")
def debug():
    """
    Debug nhanh để xem token có đúng kiểu JWT như Postman không.
    """
    t = _get_token(force_refresh=True)
    return jsonify({
        "accessKey_len": len(ACCESS_KEY),
        "token_prefix": t[:20],
        "token_suffix": t[-20:],
        "token_len": len(t),
        "looks_like_jwt": (t.count(".") == 2 and t.startswith("eyJ"))
    })


@APP.post("/api/search")
def search():
    body = request.get_json(force=True, silent=True) or {}
    search_code_raw = (body.get("searchCode") or "").strip()
    query_type = body.get("queryType", 2)

    if not search_code_raw:
        return jsonify({"ok": False, "error": "Thiếu searchCode"}), 400

    search_code = normalize_search_code(search_code_raw)

    try:
        # 1) gọi lần 1
        token = _get_token(force_refresh=False)
        http_status, j, raw = _call_code_query(token, search_code, query_type)

        # 2) nếu body báo invalid token -> refresh -> retry 1 lần
        if j is not None and _is_invalid_token_payload(j):
            _invalidate_token_cache()
            token = _get_token(force_refresh=True)
            http_status, j, raw = _call_code_query(token, search_code, query_type)

        # 3) trả kết quả
        if j is not None:
            return jsonify({
                "ok": True,
                "input": {"searchCode": search_code_raw, "normalized": search_code, "queryType": query_type},
                "httpStatus": http_status,
                "data": j
            })

        return jsonify({
            "ok": False,
            "error": "NonJSONResponse",
            "input": {"searchCode": search_code_raw, "normalized": search_code, "queryType": query_type},
            "httpStatus": http_status,
            "raw": raw
        }), 502

    except requests.HTTPError as e:
        return jsonify({
            "ok": False,
            "error": "HTTPError",
            "status": e.response.status_code if e.response else None,
            "detail": e.response.text if e.response else str(e),
        }), 502
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _decode_qr_from_bytes(image_bytes: bytes) -> str | None:
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return None
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    data = (data or "").strip()
    return data if data else None


@APP.post("/api/decode-qr")
def decode_qr():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "Thiếu file (multipart/form-data, field = file)"}), 400

    f = request.files["file"]
    image_bytes = f.read()
    if not image_bytes:
        return jsonify({"ok": False, "error": "File rỗng"}), 400

    try:
        text = _decode_qr_from_bytes(image_bytes)
        if not text:
            return jsonify({"ok": False, "error": "Không đọc được QR từ ảnh này"}), 422

        normalized = normalize_search_code(text)
        return jsonify({"ok": True, "text": text, "normalized": normalized})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=10000)