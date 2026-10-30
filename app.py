import os
import re
import json
import uuid
import secrets
import subprocess
import tempfile
import plistlib
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, request, render_template, redirect,
    url_for, session, flash, abort, jsonify, Response
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required.")

BASE_URL = os.environ.get(
    "BASE_URL", "https://shenudidkh.onrender.com"
).rstrip("/")

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_FILE = DATA_DIR / "devices.json"

TOKEN_TTL = 1800

PROFILE_SIGN_CERT = os.environ.get("PROFILE_SIGN_CERT", "")
PROFILE_SIGN_KEY = os.environ.get("PROFILE_SIGN_KEY", "")
APPLE_CA_FILE = os.environ.get("APPLE_CA_FILE", "")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")

serializer = URLSafeTimedSerializer(
    app.secret_key,
    salt="shenudid-enrollment"
)


def load_devices():
    if not DB_FILE.exists():
        return []

    try:
        return json.loads(DB_FILE.read_text("utf-8"))
    except Exception:
        return []


def save_devices(devices):
    temporary = DB_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(devices, indent=2),
        encoding="utf-8"
    )
    os.replace(temporary, DB_FILE)


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return wrapper


def create_profile(token):
    profile = {
        "PayloadType": "Profile Service",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.shenudid.profile",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": "ShenUDID Enrollment",
        "PayloadDescription": (
            "Requests your device UDID and iOS version "
            "with your permission."
        ),
        "PayloadContent": {
            "URL": f"{BASE_URL}/profile-service/{token}",
            "DeviceAttributes": [
                "UDID",
                "VERSION"
            ]
        }
    }

    return plistlib.dumps(
        profile,
        fmt=plistlib.FMT_XML
    )


def openssl_command(arguments, data=None):
    result = subprocess.run(
        ["openssl"] + arguments,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.decode("utf-8", "replace")
        )

    return result.stdout


def verify_device_response(data):
    if not APPLE_CA_FILE:
        raise RuntimeError("APPLE_CA_FILE is not configured.")

    if not Path(APPLE_CA_FILE).is_file():
        raise RuntimeError("Apple CA certificate file not found.")

    verified = openssl_command(
        [
            "cms",
            "-verify",
            "-inform", "DER",
            "-binary",
            "-CAfile", APPLE_CA_FILE,
            "-purpose", "any"
        ],
        data
    )

    attributes = plistlib.loads(verified)

    if not isinstance(attributes, dict):
        raise ValueError("Invalid device response.")

    return attributes


def create_signed_response():
    if not PROFILE_SIGN_CERT or not PROFILE_SIGN_KEY:
        raise RuntimeError(
            "Profile signing certificate and private key are required."
        )

    cert = Path(PROFILE_SIGN_CERT)
    key = Path(PROFILE_SIGN_KEY)

    if not cert.is_file() or not key.is_file():
        raise RuntimeError("Profile signing files not found.")

    response_profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.shenudid.response",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": "ShenUDID Enrollment Complete",
        "PayloadContent": []
    }

    xml = plistlib.dumps(
        response_profile,
        fmt=plistlib.FMT_XML
    )

    return openssl_command(
        [
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-outform", "DER",
            "-signer", str(cert),
            "-inkey", str(key)
        ],
        xml
    )


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/start")
def start():
    if request.form.get("consent") != "yes":
        flash("Please accept the privacy notice.", "error")
        return redirect(url_for("index"))

    token = serializer.dumps({
        "nonce": secrets.token_urlsafe(32)
    })

    return redirect(
        url_for("download_profile", token=token)
    )


@app.get("/profile/<token>.mobileconfig")
def download_profile(token):
    try:
        serializer.loads(token, max_age=TOKEN_TTL)
    except (BadSignature, SignatureExpired):
        abort(404)

    response = Response(
        create_profile(token),
        mimetype="application/x-apple-aspen-config"
    )

    response.headers["Content-Disposition"] = (
        'attachment; filename="ShenUDID.mobileconfig"'
    )

    response.headers["Cache-Control"] = "no-store"

    return response


@app.route(
    "/profile-service/<token>",
    methods=["GET", "POST"]
)
def profile_service(token):
    try:
        serializer.loads(token, max_age=TOKEN_TTL)
    except (BadSignature, SignatureExpired):
        return "Invalid or expired enrollment token.", 400

    if request.method == "GET":
        return "ShenUDID Profile Service", 200

    data = request.get_data(cache=False)

    if not data or len(data) > 2_000_000:
        return "Invalid device response.", 400

    try:
        attributes = verify_device_response(data)

        udid = str(
            attributes.get("UDID", "")
        ).strip().upper()

        version = str(
            attributes.get("VERSION", "")
        ).strip()

        if not re.fullmatch(r"[0-9A-F]{40}", udid):
            return "Invalid UDID.", 400

        if not version or len(version) > 64:
            return "Invalid iOS version.", 400

        devices = load_devices()

        if not any(
            item.get("udid") == udid
            for item in devices
        ):
            devices.append({
                "udid": udid,
                "ios_version": version,
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat()
            })

            save_devices(devices)

        signed_profile = create_signed_response()

        return Response(
            signed_profile,
            status=200,
            mimetype="application/x-apple-aspen-config",
            headers={"Cache-Control": "no-store"}
        )

    except Exception:
        app.logger.exception(
            "ShenUDID enrollment processing failed."
        )

        return (
            "Enrollment failed. Please contact the administrator.",
            400
        )


@app.get("/success")
def success():
    return render_template("success.html")


@app.get("/admin/login")
def admin_login():
    return render_template("admin_login.html")


@app.post("/admin/login")
def admin_login_post():
    password = request.form.get("password", "")

    if not ADMIN_PASSWORD_HASH:
        flash("Admin password is not configured.", "error")

    elif check_password_hash(
        ADMIN_PASSWORD_HASH,
        password
    ):
        session["admin"] = True
        return redirect(url_for("admin"))

    else:
        flash("Incorrect password.", "error")

    return redirect(url_for("admin_login"))


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin")
@admin_required
def admin():
    devices = sorted(
        load_devices(),
        key=lambda item: item.get("created_at", ""),
        reverse=True
    )

    return render_template(
        "admin.html",
        devices=devices
    )


@app.post("/admin/delete/<udid>")
@admin_required
def delete_device(udid):
    devices = [
        item for item in load_devices()
        if item.get("udid") != udid
    ]

    save_devices(devices)

    flash("Device deleted.", "success")

    return redirect(url_for("admin"))


@app.get("/admin/export.csv")
@admin_required
def export_csv():
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "UDID",
        "iOS Version",
        "Created At"
    ])

    for item in load_devices():
        writer.writerow([
            item.get("udid", ""),
            item.get("ios_version", ""),
            item.get("created_at", "")
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=shenudid.csv"
        }
    )


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "ShenUDID"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
