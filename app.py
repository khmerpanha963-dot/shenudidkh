
import os
import re
import json
import uuid
import secrets
import plistlib
import threading
import subprocess
import tempfile
import shutil

from datetime import datetime, timezone

from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    url_for,
    make_response,
    jsonify
)

from itsdangerous import URLSafeTimedSerializer
from itsdangerous.exc import BadSignature, SignatureExpired


# ==========================================
# SHENUDID CONFIGURATION
# ==========================================

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "Please configure SECRET_KEY in Render environment variables."
    )

app.secret_key = SECRET_KEY

BASE_URL = os.environ.get(
    "BASE_URL",
    "https://shenudidkh.onrender.com"
).rstrip("/")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "panhakoko99")

DATA_DIR = os.environ.get(
    "DATA_DIR",
    "/tmp/shenudid"
)

DATA_FILE = os.path.join(DATA_DIR, "udids.json")

os.makedirs(DATA_DIR, exist_ok=True)

serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="shenudid-enrollment-v1"
)

MAX_TOKEN_AGE = 3600

file_lock = threading.Lock()


# ==========================================
# CHECK OPENSSL
# ==========================================

OPENSSL = shutil.which("openssl")

if not OPENSSL:
    raise RuntimeError(
        "OpenSSL is not installed on this Render environment."
    )


# ==========================================
# SAVE UDID
# ==========================================

def save_udid(udid, ios_version):

    with file_lock:

        records = []

        if os.path.exists(DATA_FILE):

            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    records = json.load(f)

                if not isinstance(records, list):
                    records = []

            except (ValueError, OSError):
                records = []

        existing = next(
            (
                item for item in records
                if item.get("udid") == udid
            ),
            None
        )

        now = datetime.now(timezone.utc).isoformat()

        if existing:

            existing["ios_version"] = ios_version
            existing["updated_at"] = now

        else:

            records.append({
                "udid": udid,
                "ios_version": ios_version,
                "created_at": now
            })

        temp_file = DATA_FILE + ".tmp"

        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=4)

        os.replace(temp_file, DATA_FILE)


# ==========================================
# PLIST RESPONSE
# ==========================================

def plist_response(data, filename=None):

    response = make_response(
        plistlib.dumps(data, fmt=plistlib.FMT_XML)
    )

    response.headers["Content-Type"] = (
        "application/x-apple-aspen-config"
    )

    response.headers["Cache-Control"] = "no-store"

    if filename:

        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )

    return response


# ==========================================
# TOKEN SYSTEM
# ==========================================

def create_token():

    return serializer.dumps({
        "nonce": secrets.token_urlsafe(24)
    })


def validate_token(token):

    try:

        return serializer.loads(
            token,
            max_age=MAX_TOKEN_AGE
        )

    except (BadSignature, SignatureExpired):

        return None


# ==========================================
# HOME PAGE
# ==========================================

HOME = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1">

<title>ShenUDID</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #f6f7f9;
    color: #202124;
    font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
}

nav {
    height: 70px;
    background: white;
    border-bottom: 1px solid #eee;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 7%;
}

.logo {
    font-size: 21px;
    font-weight: 750;
    color: #171717;
}

.logo span {
    color: #3978e8;
}

.container {
    max-width: 650px;
    margin: 75px auto;
    padding: 20px;
}

.card {
    background: white;
    border: 1px solid #e9e9e9;
    border-radius: 18px;
    padding: 38px;
    box-shadow: 0 8px 35px rgba(0,0,0,.035);
    text-align: center;
}

.icon {
    width: 65px;
    height: 65px;
    border-radius: 18px;
    background: #edf3ff;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 22px;
    font-size: 30px;
}

h1 {
    font-size: 32px;
    margin: 0 0 12px;
}

p {
    color: #737780;
    line-height: 1.7;
    font-size: 15px;
}

button {
    width: 100%;
    border: 0;
    border-radius: 10px;
    padding: 16px;
    background: #3478f6;
    color: white;
    font-size: 16px;
    font-weight: 650;
    cursor: pointer;
    margin-top: 18px;
}

button:hover {
    background: #2465db;
}

.notice {
    text-align: left;
    background: #f7f8fa;
    padding: 17px;
    border-radius: 10px;
    margin-top: 24px;
    font-size: 13px;
    color: #656b75;
    line-height: 1.7;
}

.consent {
    display: flex;
    gap: 10px;
    text-align: left;
    align-items: flex-start;
    margin-top: 22px;
    font-size: 13px;
    color: #555;
}

.consent input {
    margin-top: 3px;
}

footer {
    text-align: center;
    color: #999;
    font-size: 12px;
    margin-top: 30px;
}

@media(max-width:600px) {

    .container {
        margin: 35px auto;
        padding: 14px;
    }

    .card {
        padding: 28px 20px;
    }

    h1 {
        font-size: 27px;
    }
}

</style>

</head>

<body>

<nav>

    <div class="logo">
        Shen<span>UDID</span>
    </div>

    <div style="font-size:13px;color:#777">
        iOS Device Service
    </div>

</nav>

<div class="container">

<div class="card">

    <div class="icon">📱</div>

    <h1>Get Your iPhone UDID</h1>

    <p>
        Identify your Apple device with our simple
        UDID enrollment process.
        Open this page in Safari on your iPhone.
    </p>

    <form action="/start" method="POST">

        <label class="consent">

            <input
                type="checkbox"
                name="consent"
                value="yes"
                required
            >

            <span>
                I understand and consent to sharing my
                device UDID and iOS version with ShenUDID.
            </span>

        </label>

        <button type="submit">
            Get My UDID →
        </button>

    </form>

    <div class="notice">

        <b>Privacy information</b><br>

        Only your UDID and iOS version are requested.
        IMEI, ICCID, contacts, photos and personal files
        are not requested.

        You can cancel installation at any time.

    </div>

</div>

<footer>
    © 2026 ShenUDID. Device identification service.
</footer>

</div>

</body>
</html>
"""


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return render_template_string(HOME)


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "ShenUDID"
    })


# ==========================================
# START ENROLLMENT
# ==========================================

@app.route("/start", methods=["POST"])
def start():

    if request.form.get("consent") != "yes":

        return "Consent is required.", 400

    token = create_token()

    return redirect(
        url_for(
            "download_profile",
            token=token
        )
    )


# ==========================================
# DOWNLOAD PROFILE
# ==========================================

@app.route("/profile/<token>.mobileconfig")
def download_profile(token):

    if not validate_token(token):

        return "Invalid or expired enrollment session.", 403

    service_url = (
        BASE_URL
        + url_for("profile_service", token=token)
    )

    profile = {

        "PayloadContent": {

            "URL": service_url,

            "DeviceAttributes": [
                "UDID",
                "VERSION"
            ]
        },

        "PayloadDescription":
            "Requests permission to share your device UDID and iOS version.",

        "PayloadDisplayName":
            "ShenUDID Enrollment",

        "PayloadIdentifier":
            "com.shenudid.profile-service",

        "PayloadOrganization":
            "ShenUDID",

        "PayloadType":
            "Profile Service",

        "PayloadUUID":
            str(uuid.uuid4()),

        "PayloadVersion": 1
    }

    return plist_response(
        profile,
        "ShenUDID.mobileconfig"
    )


# ==========================================
# APPLE PROFILE SERVICE
# ==========================================

@app.route(
    "/profile-service/<token>",
    methods=["GET", "POST"]
)
def profile_service(token):

    if not validate_token(token):

        return "Invalid enrollment session.", 403

    if request.method == "GET":

        return "ShenUDID enrollment service is ready.", 200

    raw_data = request.get_data()

    if not raw_data or len(raw_data) > 2 * 1024 * 1024:

        return "Invalid or oversized enrollment request.", 400

    try:

        # Apple sends a CMS-signed plist.
        # Extract the signed plist using OpenSSL.

        with tempfile.TemporaryDirectory() as temp_dir:

            input_file = os.path.join(
                temp_dir,
                "request.der"
            )

            output_file = os.path.join(
                temp_dir,
                "request.plist"
            )

            with open(input_file, "wb") as f:
                f.write(raw_data)

            result = subprocess.run(
                [
                    OPENSSL,
                    "cms",
                    "-verify",
                    "-inform",
                    "DER",
                    "-binary",
                    "-noverify",
                    "-in",
                    input_file,
                    "-out",
                    output_file
                ],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:

                app.logger.error(
                    "Apple CMS verification failed: %s",
                    result.stderr[:2000]
                )

                return "Apple signed request verification failed.", 400

            with open(output_file, "rb") as f:

                data = plistlib.loads(f.read())

        if not isinstance(data, dict):

            return "Invalid device information.", 400

        # Read requested attributes.

        udid = data.get("UDID")

        ios_version = data.get("VERSION")

        if not isinstance(udid, str):

            return "UDID was not supplied.", 400

        if not isinstance(ios_version, str):

            return "iOS version was not supplied.", 400

        udid = udid.strip().upper()

        ios_version = ios_version.strip()

        # Validate UDID.

        if not re.fullmatch(
            r"[0-9A-F]{40}",
            udid
        ):

            return "Invalid UDID format.", 400

        # Validate version.

        if not re.fullmatch(
            r"[0-9A-Za-z._-]{1,32}",
            ios_version
        ):

            return "Invalid iOS version format.", 400

        # Save device information.

        save_udid(
            udid,
            ios_version
        )

        app.logger.info(
            "ShenUDID enrollment completed."
        )

        # Return profile response.

        response_profile = {

            "PayloadContent": [],

            "PayloadDisplayName":
                "ShenUDID",

            "PayloadIdentifier":
                "com.shenudid.response",

            "PayloadUUID":
                str(uuid.uuid4()),

            "PayloadType":
                "Configuration",

            "PayloadVersion": 1
        }

        return plist_response(
            response_profile
        )

    except subprocess.TimeoutExpired:

        app.logger.exception(
            "Apple request processing timed out."
        )

        return "Request processing timed out.", 500

    except Exception:

        app.logger.exception(
            "ShenUDID enrollment failed."
        )

        return "Unable to process Apple enrollment request.", 400


# ==========================================
# ADMIN UDID API
# ==========================================

@app.route("/admin/udids")
def admin_udids():

    if not ADMIN_PASSWORD:

        return "Admin access is not configured.", 503

    supplied = request.headers.get(
        "X-Admin-Password",
        ""
    )

    if not secrets.compare_digest(
        supplied,
        ADMIN_PASSWORD
    ):

        return "Unauthorized", 401

    try:

        with file_lock:

            with open(
                DATA_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                records = json.load(f)

    except FileNotFoundError:

        records = []

    except (ValueError, OSError):

        return "Unable to read database.", 500

    return jsonify({
        "udids": records
    })


# ==========================================
# RUN
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
