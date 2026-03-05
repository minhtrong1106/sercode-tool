import os
import time
import requests
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv

load_dotenv()

APP = Flask(__name__, static_folder="static")

GET_TOKEN_URL = "https://trace-open-api.motul.com.sg/cncop/ca/v1/applications/get-token"
CODE_QUERY_URL = "https://trace-open-api.motul.com.sg/customer/mote/open/api/v1/codeQuery"

ACCESS_KEY = os.getenv("ACCESS_KEY", "")
SECRET_KEY_SIGN = os.getenv("SECRET_KEY_SIGN", "")

# Cache token đơn giản trong RAM
_token_cache = {
    "token": None,
    "expire_at": 0  # epoch seconds
}

def _get_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expire_at"]:
        return _token_cache["token"]

    resp = requests.post(
        GET_TOKEN_URL,
        json={"accessKey": ACCESS_KEY, "secretKeySign": SECRET_KEY_SIGN},
        timeout=20
    )
    resp.raise_for_status()
    data = resp.json()

    # ✅ Lấy token đúng kiểu response thường gặp
    token = None
    if isinstance(data, dict):
        # case 1: {"accessToken": "..."}
        if isinstance(data.get("accessToken"), str):
            token = data["accessToken"]

        # case 2: {"data": {"accessToken": "..."}}
        elif isinstance(data.get("data"), dict) and isinstance(data["data"].get("accessToken"), str):
            token = data["data"]["accessToken"]

        # case 3: {"token": "..."} hoặc {"data": "..."} (string)
        elif isinstance(data.get("token"), str):
            token = data["token"]
        elif isinstance(data.get("data"), str):
            token = data["data"]

    if not token:
        raise RuntimeError(f"Không tìm thấy accessToken trong response: {data}")

    expires_in = data.get("expiresIn") or data.get("expireIn") or 600
    try:
        expires_in = int(expires_in)
    except Exception:
        expires_in = 600

    _token_cache["token"] = token
    _token_cache["expire_at"] = time.time() + max(60, expires_in - 30)
    return token


@APP.get("/")
def index():
    return send_from_directory("static", "index.html")


@APP.post("/api/search")
def search():
    body = request.get_json(force=True, silent=True) or {}
    search_code = (body.get("searchCode") or "").strip()
    query_type = body.get("queryType", 2)

    if not search_code:
        return jsonify({"ok": False, "error": "Thiếu searchCode"}), 400

    try:
        token = _get_token()

        resp = requests.post(
            CODE_QUERY_URL,
            headers={
                # Ảnh bạn cho thấy Authorization = token (không chắc có cần 'Bearer ' hay không)
                "Authorization": token,
                "Content-Type": "application/json"
            },
            json={"searchCode": search_code, "queryType": query_type},
            timeout=25
        )

        # Nếu server yêu cầu "Bearer <token>", bạn đổi dòng Authorization thành:
        # "Authorization": f"Bearer {token}"

        resp.raise_for_status()
        return jsonify({"ok": True, "data": resp.json()})

    except requests.HTTPError as e:
        return jsonify({
            "ok": False,
            "error": "HTTPError",
            "status": e.response.status_code if e.response else None,
            "detail": e.response.text if e.response else str(e),
        }), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


#if __name__ == "__main__":
    #APP.run(host="0.0.0.0", port=8080, debug=True)
if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=10000)
