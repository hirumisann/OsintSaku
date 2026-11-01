#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
import asyncio
from phonsint.core.parser import parse_phone_number
from phonsint.modules.social.facebook import validate_facebook
from phonsint.modules.social.instagram import validate_instagram

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#  config
GTC_BASE = "https://pbssrv-centralevents.com"
VFK_BASE = "https://api.verifykit.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
VFK_HMAC_KEY = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932"
VFK_CLIENT_KEY = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d"
VFK_FINAL_KEY = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

APP_VERSION = "8.4.0"
ANDROID_OS = "android 9"
LANG = "en_US"
COUNTRY = "id"
DEVICE_NAME = "SM-G977N"
TIME_ZONE = "Asia/Bangkok"
BUNDLE_ID = "app.source.getcontact"
CARRIER = ("510", "Indosat Ooredoo", "01")

# Diffie-Hellman params
DH_P = 900719898367
DH_G = 7

CONFIG_DIR = Path(os.environ.get("GTC_CONFIG_DIR", Path.home() / ".config" / "gtc"))
CRED_FILE = CONFIG_DIR / "credentials.json"
RESULTS_DIR = Path(os.environ.get("GTC_RESULTS_DIR", Path(__file__).resolve().parent / "results"))


class GtcError(Exception):
    pass


#  crypto
def _sig(ts: str, message: str, key_hex: str) -> str:
    mac = hmac.new(bytes.fromhex(key_hex), f"{ts}-{message}".encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def encrypt(data: str, key_hex: str) -> str:
    enc = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(_pad(data.encode())) + enc.finalize()).decode()


def decrypt(data: str, key_hex: str) -> str:
    dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).decryptor()
    out = dec.update(base64.b64decode(data)) + dec.finalize()
    return out[: -out[-1]].decode()


def dh_keypair() -> tuple[int, int]:
    priv = secrets.randbelow(10**8 - 10**6) + 10**6
    return priv, pow(DH_G, priv, DH_P)


def dh_final_key(priv: int, server_pub: int) -> str:
    return hashlib.sha256(str(pow(int(server_pub), priv, DH_P)).encode()).hexdigest()


def _ts() -> str:
    return str(int(time.time() * 1000))


def new_device_id() -> str:
    return secrets.token_hex(8)


#  http
def _post(url: str, body: str, headers: dict, timeout: int = 25) -> requests.Response:
    return requests.post(url, data=body, headers=headers, timeout=timeout)


def gtc_call(endpoint: str, payload: dict, *, token: str, final_key: str,
             device_id: str, encrypted: bool = True) -> tuple[int, dict]:
    """POST to a GetContact endpoint. Returns (http_code, decrypted_json)."""
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": device_id,
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1" if encrypted else "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if token:
        headers["x-token"] = token
    body = json.dumps({"data": encrypt(raw, final_key)}) if encrypted else raw
    r = _post(GTC_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if encrypted and "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], final_key))
    return r.status_code, parsed


def vfk_call(endpoint: str, payload: dict, device_id: str) -> tuple[int, dict]:
    """VerifyKit call — fixed version (compact JSON + App-Version 8.16.0)."""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "X-VFK-Client-Device-Id": device_id,
        "X-VFK-Client-Key": VFK_CLIENT_KEY,
        "X-VFK-Sdk-Version": "0.11.4",
        "X-VFK-Os": "android 9.0",
        "X-VFK-App-Version": "8.16.0",         
        "X-VFK-Encrypted": "1",
        "X-VFK-Lang": "in_ID",
        "X-VFK-Req-Timestamp": ts,
        "X-VFK-Req-Signature": _sig(ts, raw, VFK_HMAC_KEY),
    }
    body = json.dumps({"data": encrypt(raw, VFK_FINAL_KEY)}, separators=(",", ":"))
    r = _post(VFK_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], VFK_FINAL_KEY))
    return r.status_code, parsed


def dig(obj, path, default=None):
    for k in path.split("."):
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj


#  store
def load_store() -> dict:
    if not CRED_FILE.exists():
        return {"active": None, "credentials": {}}
    return json.loads(CRED_FILE.read_text("utf-8"))


def save_store(store: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CRED_FILE.write_text(json.dumps(store, indent=2), "utf-8")
    try:
        os.chmod(CRED_FILE, 0o600)
    except OSError:
        pass


def get_cred(store: dict, name: str | None) -> tuple[str, dict]:
    name = name or store.get("active")
    creds = store.get("credentials", {})
    if not name or name not in creds:
        raise GtcError("No active credential. Run: gtc cred list / gtc cred use <name>")
    return name, creds[name]


def normalize_phone(raw: str) -> str:
    p = re.sub(r"[^\d+]", "", raw.strip())
    if p.startswith("+"):
        return p
    if p.startswith("0"):
        return "+62" + p[1:]
    if p.startswith("62"):
        return "+" + p
    raise GtcError(f"Invalid phone number: {raw}")


#  features
def api_search(cred: dict, phone: str, source: str) -> dict:
    endpoint = "/v2.8/number-detail" if source == "tags" else "/v2.8/search"
    payload = {
        "countryCode": COUNTRY,
        "phoneNumber": phone,
        "source": "profile" if source == "tags" else "search",
        "token": cred["token"],
    }
    code, body = gtc_call(endpoint, payload, token=cred["token"],
                          final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    meta = dig(body, "meta.httpStatusCode")
    if code != 200 or meta != 200:
        raise GtcError(f"HTTP {code}/{meta}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def api_subscription(cred: dict) -> dict:
    code, body = gtc_call("/v2.8/subscription", {"token": cred["token"]},
                          token=cred["token"], final_key=cred["finalKey"],
                          device_id=cred["clientDeviceId"])
    if code != 200:
        raise GtcError(f"HTTP {code}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def show_captcha(b64_image: str) -> Path:
    path = Path(tempfile.gettempdir()) / f"gtc_captcha_{int(time.time())}.jpg"
    path.write_bytes(base64.b64decode(b64_image))
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass
    return path


#  commands
def _spin(label: str, seconds: float = 1.0) -> None:
    """Animasi spinner singkat sebelum hasil tampil."""
    if not sys.stdout.isatty():
        time.sleep(seconds)
        return
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end = time.time() + seconds
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r  {A.PINK}{frames[i % len(frames)]}{A.RESET}  {A.GRAY}{label}{A.RESET}")
        sys.stdout.flush()
        time.sleep(0.07)
        i += 1
    sys.stdout.write("\r" + " " * (len(label) + 8) + "\r")
    sys.stdout.flush()


def _field(label: str, value: str, width: int = 14) -> str:
    val = value if value and value != "-" else f"{A.GRAY}—{A.RESET}"
    lab = label[:1].upper() + label[1:]
    return f"  {A.CYAN}▸{A.RESET} {A.GRAY}{lab:<{width}}{A.RESET} {A.WHITE}{A.BOLD}{val}{A.RESET}"

def cmd_search(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    phone = normalize_phone(args.phone)

    _spin("Menghubungi server...", 0.9)
    body = api_search(cred, phone, args.type)
    _spin("Memproses data...", 0.5)

    if args.json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0

    profile = dig(body, "result.profile")
    tags = dig(body, "result.tags")

    if _tty():
        print(f"\n  {A.PURPLE}{'═'*48}{A.RESET}")
        print(f"  {A.PINK}{A.BOLD}  ✦  HASIL PENCARIAN  ✦{A.RESET}")
        print(f"  {A.PURPLE}{'═'*48}{A.RESET}\n")
        print(f"  {A.CYAN}▸{A.RESET} {A.GRAY}{'Akun':<14}{A.RESET} {A.WHITE}{name}{A.RESET}")
        print(f"  {A.CYAN}▸{A.RESET} {A.GRAY}{'Nomor':<14}{A.RESET} {A.WHITE}{A.BOLD}{phone}{A.RESET}")
        print(f"  {A.PURPLE}{'─'*48}{A.RESET}\n")

        if profile:
            print(f"  {A.PINK}{A.BOLD}PROFIL{A.RESET}\n")
            for k, label in (
                ("displayName", "nama tampilan"),
                ("name", "nama depan"),
                ("surname", "nama belakang"),
                ("phoneNumber", "nomor"),
                ("displayNumber", "format tampil"),
                ("tagCount", "jumlah tag"),
                ("email", "email"),
            ):
                print(_field(label, str(profile.get(k) or "-")))
            print()

        if tags:
            print(f"  {A.PINK}{A.BOLD}TAG ({len(tags)}){A.RESET}\n")
            for i, t in enumerate(tags, 1):
                tag = t.get("tag", "-")
                cnt = t.get("count", "")
                print(f"  {A.CYAN}[{i}]{A.RESET} {A.WHITE}{A.BOLD}{tag}{A.RESET}  {A.GRAY}x{cnt}{A.RESET}")
            print()

        if not profile and not tags:
            print(json.dumps(body, indent=2, ensure_ascii=False))

        print(f"  {A.PURPLE}{'─'*48}{A.RESET}\n")
    else:
        print(f"[{name}] {phone}")
        if profile:
            for k in ("displayName", "name", "surname", "phoneNumber", "displayNumber", "tagCount", "email"):
                print(f"  {k:<14}: {profile.get(k) or '-'}")
        if tags:
            print(f"  tags ({len(tags)}):")
            for t in tags:
                print(f"    - {t.get('tag')}  x{t.get('count', '')}")
        if not profile and not tags:
            print(json.dumps(body, indent=2, ensure_ascii=False))
    return 0


def cmd_batch(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    with open(args.csv, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        raise GtcError("Empty CSV")
    header = rows[0]
    col = 0
    if any(h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor") for h in header):
        col = next(i for i, h in enumerate(header)
                   if h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor"))
        rows = rows[1:]
    out = csv.writer(sys.stdout if args.out == "-" else open(args.out, "w", newline="", encoding="utf-8"))
    out.writerow(["phone", "status", "displayName", "tagCount", "tags", "error"])
    for row in rows:
        if not row or not row[col].strip():
            continue
        raw = row[col].strip()
        try:
            phone = normalize_phone(raw)
            body = api_search(cred, phone, args.type)
            prof = dig(body, "result.profile") or {}
            tags = [t.get("tag", "") for t in (dig(body, "result.tags") or [])]
            out.writerow([phone, "ok", prof.get("displayName", ""),
                          prof.get("tagCount", len(tags)), "|".join(tags), ""])
            print(f"ok   {phone}", file=sys.stderr)
        except Exception as e:
            out.writerow([raw, "error", "", "", "", str(e)])
            print(f"FAIL {raw}: {e}", file=sys.stderr)
        time.sleep(args.delay)
    return 0

def _bar(used: int, limit: int, width: int = 20) -> str:
    if limit <= 0:
        return f"{A.GRAY}{'░' * width}{A.RESET}"
    filled = int(width * used / limit)
    filled = max(0, min(width, filled))
    return f"{A.PINK}{'█' * filled}{A.RESET}{A.GRAY}{'░' * (width - filled)}{A.RESET}"


def cmd_quota(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    body = api_subscription(cred)
    if args.json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0

    u = dig(body, "result.subscriptionInfo.usage") or {}
    renew = dig(body, "result.subscriptionInfo.renewDate", "-")

    if _tty():
        print(f"\n  {A.PURPLE}{'═'*52}{A.RESET}")
        print(f"  {A.PINK}{A.BOLD}  ✦  SISA KUOTA  ✦{A.RESET}")
        print(f"  {A.PURPLE}{'═'*52}{A.RESET}\n")
        print(f"  {A.CYAN}▸{A.RESET} {A.GRAY}{'Akun':<12}{A.RESET} {A.WHITE}{A.BOLD}{name}{A.RESET}")
        print(f"  {A.CYAN}▸{A.RESET} {A.GRAY}{'Nomor':<12}{A.RESET} {A.WHITE}{cred.get('phoneNumber', '-')}{A.RESET}")
        print(f"  {A.PURPLE}{'─'*52}{A.RESET}\n")

        labels = {"search": "Pencarian", "numberDetail": "Detail nomor"}
        for key in ("search", "numberDetail"):
            d = u.get(key) or {}
            remaining = d.get("remainingCount", 0) or 0
            limit = d.get("limit", 0) or 0
            used = max(0, limit - remaining)
            label = labels.get(key, key)
            print(f"  {A.WHITE}{A.BOLD}{label:<14}{A.RESET} {A.GRAY}{remaining}/{limit}{A.RESET}")
            print(f"    {_bar(used, limit)}\n")

        print(f"  {A.CYAN}▸{A.RESET} {A.GRAY}{'Perpanjang':<14}{A.RESET} {A.WHITE}{A.BOLD}{renew}{A.RESET}")
        print(f"  {A.PURPLE}{'─'*52}{A.RESET}\n")
    else:
        print(f"[{name}]")
        for key in ("search", "numberDetail"):
            d = u.get(key) or {}
            print(f"  {key:<13}: {d.get('remainingCount', '?')}/{d.get('limit', '?')} remaining")
        print(f"  renewDate    : {renew}")
    return 0


def cmd_captcha(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    common = dict(token=cred["token"], final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    code, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
    image = dig(body, "result.image")
    if not image:
        raise GtcError(f"No captcha returned (HTTP {code}). Account may not be blocked.")
    while True:
        path = show_captcha(image)
        print(f"Captcha image: {path}")
        answer = input("Enter captcha code (blank = refresh, 'q' = quit): ").strip()
        if answer.lower() == "q":
            return 1
        if not answer:
            _, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
            image = dig(body, "result.image") or image
            continue
        code, body = gtc_call("/v2.8/verify-code",
                              {"validationCode": answer, "token": cred["token"]}, **common)
        if code == 200 and dig(body, "meta.httpStatusCode") == 200:
            print("Captcha verified.")
            return 0
        print("Wrong code, new captcha issued.")
        image = dig(body, "result.image") or image


def cmd_generate(args) -> int:
    raw_phone = args.phone.strip()
    phone = normalize_phone(raw_phone)
    device_id = new_device_id()
    priv, pub = dh_keypair()

    # 1. register -> token + server public key
    ts = _ts()
    reg_body = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY, "deepLink": None,
        "deviceName": DEVICE_NAME, "deviceType": "Android", "email": None,
        "notificationToken": "", "oldToken": None, "peerKey": pub,
        "timeZone": TIME_ZONE, "token": "",
    }
    raw = json.dumps(reg_body, ensure_ascii=False)
    r = _post(GTC_BASE + "/v2.8/register", raw, {
        "Content-Type": "application/json", "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION, "x-client-device-id": device_id, "x-lang": LANG,
        "x-req-timestamp": ts, "x-country-code": COUNTRY, "x-encrypted": "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    })
    if r.status_code != 201:
        raise GtcError(f"register failed: HTTP {r.status_code} {r.text[:200]}")
    reg = r.json()
    token = dig(reg, "result.token")
    server_key = dig(reg, "result.serverKey")
    if not token or not server_key:
        raise GtcError(f"register: missing token/serverKey: {reg}")
    final_key = dh_final_key(priv, server_key)
    print(f"clientDeviceId : {device_id}")
    print(f"finalKey       : {final_key}")
    print(f"token          : {token}")

    common = dict(token=token, final_key=final_key, device_id=device_id)
    base = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY,
        "deviceName": DEVICE_NAME, "notificationToken": "", "timeZone": TIME_ZONE,
        "token": token,
    }
    steps = [
        ("/v2.8/init-basic", base, 201),
        ("/v2.8/ad-settings", {"source": "init", "token": token}, 200),
        ("/v2.8/init-intro", {**base, "hasRouting": False}, 201),
        ("/v2.8/email-code-validate/start",
         {"email": f"user{random.randint(10**7, 10**8 - 1)}@gmail.com",
          "fullName": f"User{random.randint(1000, 999999)}", "token": token}, 200),
        ("/v2.8/country", {"countryCode": COUNTRY.upper(), "token": token}, 200),
        ("/v2.8/validation-start",
         {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token}, 200),
    ]
    for endpoint, payload, want in steps:
        code, body = gtc_call(endpoint, payload, **common)
        if code != want:
            raise GtcError(f"{endpoint} failed: HTTP {code}")
        print(f"  ok {endpoint}")

    # ---------- VerifyKit (fixed) ----------
    # 1. INIT
    code, body = vfk_call("/v2.0/init", {
        "isCallPermissionGranted": True,
        "countryCode": "ID",
        "deviceName": DEVICE_NAME,
        "installedApps": '{"whatsapp":0,"telegram":0,"viber":0}',
        "outsideCountryCode": "ID",
        "outsidePhoneNumber": raw_phone,  
        "timezone": TIME_ZONE,
        "bundleId": BUNDLE_ID,
    }, device_id)
    if code != 200:
        raise GtcError(f"vfk init failed: HTTP {code} — {dig(body, 'message') or dig(body, 'error') or body}")

    # 2. COUNTRY
    code, body = vfk_call("/v2.0/country", {
        "countryCode": "ID",
        "bundleId": BUNDLE_ID,
    }, device_id)
    if code != 200:
        raise GtcError(f"vfk country failed: HTTP {code}")

    # 3. START → WhatsApp deeplink
    code, body = vfk_call("/v2.0/start", {
        "countryCode": "ID",
        "mcc": CARRIER[0],
        "mnc": CARRIER[2],
        "phoneNumber": phone,  # E.164
        "app": "whatsapp",
        "bundleId": BUNDLE_ID,
    }, device_id)
    deeplink = dig(body, "result.deeplink")
    reference = dig(body, "result.reference")
    if not deeplink or not reference:
        raise GtcError(f"vfk start failed (HTTP {code}): {body}")

    codes = re.findall(r"\*(.*?)\*", urllib.parse.unquote(deeplink))
    verification = next((c for c in codes if re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", c)), None)

    gtc_call("/v2.8/validation-start",
             {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token},
             **common)

    print("\nSend the WhatsApp verification message, then come back:")
    print(f"  link : {deeplink}")
    print(f"  code : {verification}")
    input("\nPress Enter after WhatsApp shows two checkmarks... ")

    # 4. CHECK → sessionId → gtc verifykit-result
    code, body = vfk_call("/v2.0/check", {
        "reference": reference,
        "bundleId": BUNDLE_ID,
    }, device_id)
    session_id = dig(body, "result.sessionId")
    if not session_id:
        raise GtcError(f"Verification not completed yet (HTTP {code}): {body}")

    code, body = gtc_call("/v2.8/verifykit-result",
                          {"sessionId": session_id, "token": token}, **common)
    validation_date = dig(body, "result.validationDate")
    if not validation_date:
        raise GtcError(f"verifykit-result failed (HTTP {code}): {body}")

    store = load_store()
    name = args.name or phone
    store.setdefault("credentials", {})[name] = {
        "description": args.description or f"Generated {validation_date}",
        "phoneNumber": phone,
        "clientDeviceId": device_id,
        "finalKey": final_key,
        "token": token,
        "validationDate": validation_date,
    }
    store["active"] = store.get("active") or name
    save_store(store)
    print(f"\nVerified {validation_date}. Saved as '{name}' in {CRED_FILE}")
    return 0


def cmd_cred(args) -> int:
    store = load_store()
    creds = store.setdefault("credentials", {})

    if args.cred_cmd == "list":
        if not creds:
            print("No credentials. Add one: gtc cred add <name> --final-key ... --token ...")
            return 0

        if _tty():
            active = store.get("active") or "-"
            print(f"\n  {A.PURPLE}{'═'*56}{A.RESET}")
            print(f"  {A.PINK}{A.BOLD}  ✦  AKUN TERSIMPAN  ✦{A.RESET}")
            print(f"  {A.PURPLE}{'═'*56}{A.RESET}\n")
            print(f"  {A.GRAY}{'':<2}{'Nomor':<18}{'Deskripsi'}{A.RESET}")
            print(f"  {A.PURPLE}{'─'*56}{A.RESET}")
            for name, c in creds.items():
                mark = f"{A.PINK}{A.BOLD}*{A.RESET}" if name == active else " "
                phone = c.get("phoneNumber") or "-"
                desc = c.get("description") or "-"
                if len(desc) > 32:
                    desc = desc[:29] + "..."
                print(f"  {mark} {A.WHITE}{A.BOLD}{phone:<18}{A.RESET}{A.GRAY}{desc}{A.RESET}")
            print(f"  {A.PURPLE}{'─'*56}{A.RESET}\n")
            print(f"  {A.CYAN}▸{A.RESET} {A.GRAY}{'Aktif':<14}{A.RESET} {A.WHITE}{A.BOLD}{active}{A.RESET}\n")
        else:
            for name, c in creds.items():
                mark = "*" if name == store.get("active") else " "
                print(f"{mark} {name:<20} {c.get('phoneNumber', '-'):<16} {c.get('description', '')}")
        return 0

    if args.cred_cmd == "add":
        creds[args.name] = {
            "description": args.description or "",
            "phoneNumber": args.phone or "",
            "clientDeviceId": args.device_id or new_device_id(),
            "finalKey": args.final_key,
            "token": args.token,
        }
        store["active"] = store.get("active") or args.name
        save_store(store)
        print(f"Saved '{args.name}' to {CRED_FILE}")
        return 0

    if args.cred_cmd == "use":
        if args.name not in creds:
            raise GtcError(f"Unknown credential: {args.name}")
        store["active"] = args.name
        save_store(store)
        print(f"Active credential: {args.name}")
        return 0

    if args.cred_cmd == "remove":
        if creds.pop(args.name, None) is None:
            raise GtcError(f"Unknown credential: {args.name}")
        if store.get("active") == args.name:
            store["active"] = next(iter(creds), None)
        save_store(store)
        print(f"Removed '{args.name}'")
        return 0

    raise GtcError("unknown cred subcommand")


#  cli
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gtc", description="GetContact CLI")
    p.add_argument("-a", "--account", help="credential name (default: active)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search", help="look up a phone number")
    s.add_argument("phone")
    s.add_argument("-t", "--type", choices=["profile", "tags"], default="profile")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_search)

    b = sub.add_parser("batch", help="look up every number in a CSV")
    b.add_argument("csv")
    b.add_argument("-t", "--type", choices=["profile", "tags"], default="tags")
    b.add_argument("-o", "--out", default="-", help="output CSV path (default stdout)")
    b.add_argument("--delay", type=float, default=1.5, help="seconds between requests")
    b.set_defaults(func=cmd_batch)

    q = sub.add_parser("quota", help="show subscription usage")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_quota)

    c = sub.add_parser("captcha", help="solve the captcha interactively (403 unblock)")
    c.set_defaults(func=cmd_captcha)

    g = sub.add_parser("generate", help="generate a new credential via DH + WhatsApp")
    g.add_argument("phone")
    g.add_argument("--name", help="store under this name (default: phone)")
    g.add_argument("--description")
    g.set_defaults(func=cmd_generate)

    cr = sub.add_parser("cred", help="manage stored credentials")
    crs = cr.add_subparsers(dest="cred_cmd", required=True)
    crs.add_parser("list").set_defaults(func=cmd_cred)
    a = crs.add_parser("add")
    a.add_argument("name")
    a.add_argument("--final-key", required=True)
    a.add_argument("--token", required=True)
    a.add_argument("--device-id")
    a.add_argument("--phone")
    a.add_argument("--description")
    a.set_defaults(func=cmd_cred)
    u = crs.add_parser("use")
    u.add_argument("name")
    u.set_defaults(func=cmd_cred)
    rm = crs.add_parser("remove")
    rm.add_argument("name")
    rm.set_defaults(func=cmd_cred)
    return p


# ── ANSI helpers ─────────────────────────────────────────────────────────────
class A:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    PINK    = "\033[38;5;213m"
    PURPLE  = "\033[38;5;141m"
    BLUE    = "\033[38;5;111m"
    VIOLET  = "\033[38;5;99m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    GREEN   = "\033[92m" # <-- TAMBAHKAN INI
    RED     = "\033[91m" # <-- TAMBAHKAN INI (untuk berjaga-jaga)


def _tty() -> bool:
    return sys.stdout.isatty()

# ── Anime banner ─────────────────────────────────────────────────────────────
ANIME_BANNER = [
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣷⢸⣿⣿⡜⢯⣷⡌⡻⣿⣿⣿⣆⢈⠻⠿⢿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡁⢳⣿⣿⣿⣿⣿⣿⡜⣿⣿⣧⢀⢻⣷⠰⠈⢿⣿⣿⣧⢣⠉⠑⠪⢙⠿⠿⠿⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣱⡇⡞⣿⣿⣿⣿⣿⣿⡇⣿⣿⡏⡄⣧⠹⡇⠧⠈⢻⣿⣿⡇⢧⢢⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⢃⢿⣿⣿⣿⣿⣿⣷⣿⣿⠇⢃⣡⣤⡹⠐⣿⣀⢻⣿⣿⢸⡎⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣾⣿⣿⠘⡸⣿⣿⣿⣿⣿⣿⣿⡿⣰⣿⣿⢟⡷⠈⠋⠃⠎⢿⣿⡏⣿⠀⠘⢆⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⡐⢹⣿⣿⡐⢡⢹⣿⣿⣿⣿⡏⣿⢣⣿⣿⡑⠁⠔⠀⠉⠉⠢⡘⣿⡇⣿⡇⠀⡀⠡⡀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠘⣿⣿⣇⠇⢣⢻⣿⣿⣿⡇⢇⣾⣿⣿⡆⢸⣤⡀⠚⢂⠀⢡⢿⡇⣿⡇⠀⢿⠀⠀⠄⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠠⠹⣿⣿⡘⣆⢣⠻⣿⣿⢈⣾⣿⣿⣿⣶⣸⣏⢀⣬⣋⡼⣠⢸⢹⣿⡇⢠⣼⠙⡄⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠁⠹⣿⣇⠹⡃⠃⠙⡇⠘⢿⣿⣿⣿⣿⣿⣏⣓⣉⣭⣴⣿⠘⢸⣿⠁⠘⠋⠀⠹⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⠀⠀⠈⢿⣇⠂⣷⠄⠐⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢠⢸⡏⠀⢀⣠⣴⣾⣿⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠙⠆⠈⠢⠲⠥⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡞⣸⠁⠀⢸⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠄⠃⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⡏⠹⣿⣿⡿⠫⠊⠀⠀⠀⣶⠀⢻⣿⣿⣿⣿⡿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠻⠿⠿⠿⢋⠀⠀⠀⠀⢀⣼⣿⡆⠈⣿⣿⣿⡟⣱⡷⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢁⣁⡀⠨⣛⠿⠶⠄⢀⣠⣾⣿⣿⣷⠀⢹⣿⡟⣴⠈⢃⣶⠔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⡄⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠈⣿⣿⡿⠀⡀⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢙⠻⣿⣿⢀⠙⠻⠿⣿⣿⣿⣿⣿⣿⡇⠁⣿⠟⡀⠈⣧⢰⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠿⠴⠮⣥⠻⢧⣤⣄⣀⡉⢩⣭⣍⣃⣀⣩⠎⢀⣼⠉⣼⡯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠁⣛⠓⢒⣒⣢⡭⢁⡈⠿⠿⠟⠹⠛⠁⠀⠀⠀⠰⠃⠂⠀⠀⠀",
]

BANNER_COLORS = [
    A.VIOLET, A.VIOLET, A.PURPLE, A.PURPLE,
    A.MAGENTA, A.MAGENTA, A.PINK, A.PINK,
    A.PINK, A.MAGENTA, A.MAGENTA, A.PURPLE,
    A.PURPLE, A.BLUE, A.BLUE, A.CYAN,
    A.CYAN, A.CYAN, A.BLUE,
]


def print_anime_banner() -> None:
    print()
    if _tty():
        for line, color in zip(ANIME_BANNER, BANNER_COLORS):
            print(f"{color}{A.BOLD}{line}{A.RESET}")
        print(f"\n        {A.PINK}{A.BOLD}O S I N T S A K U{A.RESET}")
        print(f"        {A.CYAN}┈┈┈  Anime Edition  ┈┈┈{A.RESET}\n")
        print(f"        {A.GRAY}✦  {A.WHITE}Muhammad Hilmy  {A.GRAY}✦{A.RESET}")
        print(f"        {A.MAGENTA}Instagram{A.RESET} {A.GRAY}→{A.RESET} {A.CYAN}@hirumisann{A.RESET}")
        print(f"        {A.MAGENTA}GitHub   {A.RESET} {A.GRAY}→{A.RESET} {A.CYAN}hirumisann{A.RESET}")
        print(f"        {A.GRAY}https://instagram.com/hirumisann{A.RESET}")
        print(f"        {A.GRAY}https://github.com/hirumisann{A.RESET}\n")
        print(f"        {A.PURPLE}{'─'*46}{A.RESET}\n")
    else:
        for line in ANIME_BANNER:
            print(line)
        print("\n        O S I N T S A K U")
        print("        ┈┈┈  Anime Edition  ┈┈┈\n")
        print("        ✦  Muhammad Hilmy  ✦")
        print("        Instagram → @hirumisann")
        print("        GitHub    → hirumisann")
        print("        https://instagram.com/hirumisann")
        print("        https://github.com/hirumisann\n")
        print(f"        {'─'*46}\n")


def print_startup(args) -> None:
    tty = sys.stderr.isatty()
    c, d, r = ("\033[38;5;141m", "\033[2m", "\033[0m") if tty else ("", "", "")
    store = load_store() if CRED_FILE.exists() else {}
    active = store.get("active") or "-"
    n = len(store.get("credentials", {}))
    print(f"{d}  Version   {APP_VERSION} | App {BUNDLE_ID}{r}", file=sys.stderr)
    print(f"{d}  Config    {CONFIG_DIR}{r}", file=sys.stderr)
    print(f"{d}  Account   {getattr(args, 'account', None) or active} ({n} stored){r}", file=sys.stderr)
    print(f"{d}  Command   {args.cmd}{r}\n", file=sys.stderr)

def print_startup(args) -> None:
    tty = sys.stderr.isatty()
    c, d, r = ("\033[38;5;141m", "\033[2m", "\033[0m") if tty else ("", "", "")
    store = load_store() if CRED_FILE.exists() else {}
    active = store.get("active") or "-"
    n = len(store.get("credentials", {}))
    print(f"{d}  Version   {APP_VERSION} | App {BUNDLE_ID}{r}", file=sys.stderr)
    print(f"{d}  Config    {CONFIG_DIR}{r}", file=sys.stderr)
    print(f"{d}  Account   {getattr(args, 'account', None) or active} ({n} stored){r}", file=sys.stderr)
    print(f"{d}  Command   {args.cmd}{r}\n", file=sys.stderr)


class _Tee:
    def __init__(self, stream, fh):
        self._s, self._f = stream, fh

    def write(self, s):
        self._s.write(s)
        self._f.write(s)
        return len(s)

    def flush(self):
        self._s.flush()
        self._f.flush()

    def __getattr__(self, name):
        return getattr(self._s, name)


def open_result_file(args) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    parts = [time.strftime("%Y%m%d-%H%M%S"), args.cmd]
    for extra in (getattr(args, "phone", None), getattr(args, "action", None)):
        if extra:
            parts.append(re.sub(r"[^0-9A-Za-z_.-]", "_", str(extra)))
    ext = "json" if getattr(args, "json", False) else "txt"
    return RESULTS_DIR / f"{'-'.join(parts)}.{ext}"


MENU = [
    ("Cari profil nomor", "Nama pemilik", "profile"),
    ("Cari tag nomor", "Nama tersimpan orang lain", "tags"),
    ("Pindai medsos (IG/FB)", "Cek akun terdaftar", "phonsint_scan"), # <-- Tambahkan ini
    ("Sisa kuota akun", "Cek limit harian", "quota"),
    ("Cari banyak nomor dari CSV", "Batch lookup", "batch"),
    ("Buka blokir / captcha", "Verifikasi manual", "captcha"),
    ("Lihat akun tersimpan", "Daftar kredensial", "credlist"),
    ("Tambah akun baru", "Butuh WhatsApp", "generate"),
]


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return "0"


def interactive() -> int:
    print_anime_banner()
    while True:
        if _tty():
            print(f"  {A.PURPLE}{'═'*52}{A.RESET}")
            print(f"  {A.PINK}{A.BOLD}  ✦  PILIH FITUR  ✦{A.RESET}")
            print(f"  {A.PURPLE}{'═'*52}{A.RESET}")
            for i, (label, desc, _) in enumerate(MENU, 1):
                num = f"{A.CYAN}{A.BOLD}[{i}]{A.RESET}"
                name = f"{A.WHITE}{A.BOLD}{label}{A.RESET}"
                hint = f"{A.GRAY}{desc}{A.RESET}"
                print(f"  {num} {name}  {hint}")
            print(f"  {A.GRAY}[0]{A.RESET} {A.WHITE}Keluar{A.RESET}")
            print(f"  {A.PURPLE}{'═'*52}{A.RESET}\n")
        else:
            print("Pilih fitur:")
            for i, (label, desc, _) in enumerate(MENU, 1):
                print(f"  {i}. {label} ({desc})")
            print("  0. Keluar\n")

        if _tty():
            choice = ask(f"  {A.PINK}▸{A.RESET} {A.BOLD}Nomor pilihan:{A.RESET} ")
        else:
            choice = ask("Nomor pilihan: ")

        if choice in ("0", "q", "keluar", ""):
            if _tty():
                print(f"\n  {A.CYAN}Sampai jumpa.{A.RESET}\n")
            return 0

        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(MENU)):
                print(f"  {A.GRAY}Pilihan tidak valid.{A.RESET}\n")
                continue
        except ValueError:
            print(f"  {A.GRAY}Masukkan angka.{A.RESET}\n")
            continue

        action = MENU[idx][2]
        try:
            if action == "profile":
                phone = ask("  Nomor telepon: ")
                sys.argv = ["gtc", "search", phone, "-t", "profile"]
            elif action == "tags":
                phone = ask("  Nomor telepon: ")
                sys.argv = ["gtc", "search", phone, "-t", "tags"]
            elif action == "quota":
                sys.argv = ["gtc", "quota"]
            elif action == "batch":
                csv_path = ask("  Path file CSV: ")
                sys.argv = ["gtc", "batch", csv_path]
            elif action == "captcha":
                sys.argv = ["gtc", "captcha"]
            elif action == "credlist":
                sys.argv = ["gtc", "cred", "list"]
            elif action == "generate":
                phone = ask("  Nomor WhatsApp (untuk verifikasi): ")
                sys.argv = ["gtc", "generate", phone]
                
            # --- TAMBAHKAN BLOK INI ---
            elif action == "phonsint_scan":
                raw_phone = ask("  Nomor telepon (contoh: +628...): ")
                
                # 1. Parsing nomor
                phone_info = parse_phone_number(raw_phone)
                if not phone_info.is_valid:
                    print(f"  {A.GRAY}Nomor tidak valid. Pastikan pakai kode negara (+62).{A.RESET}\n")
                    continue

                print(f"\n  {A.PINK}⠋{A.RESET} {A.GRAY}Memindai akun medsos untuk {phone_info.e164}...{A.RESET}\n")
                
                try:
                    # 2. Jalankan scanner secara async
                    async def run_social_scans():
                        # Jalankan FB dan IG secara bersamaan
                        fb_task = validate_facebook(phone_info)
                        ig_task = validate_instagram(phone_info)
                        return await asyncio.gather(fb_task, ig_task)

                    fb_res, ig_res = asyncio.run(run_social_scans())

                    # 3. Tampilkan hasil FB
                    print(f"  {A.PINK}{A.BOLD}FACEBOOK{A.RESET}")
                    if fb_res.is_found():
                        print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Status     : {A.GREEN}{A.BOLD}Terdaftar{A.RESET}")
                        if "name" in fb_res.extra:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Nama       : {fb_res.extra['name']}{A.RESET}")
                        if "matched_accounts" in fb_res.extra:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Akun Lain  : {fb_res.extra['profiles']}{A.RESET}")
                        if "email" in fb_res.extra:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Email      : {fb_res.extra['email']}{A.RESET}")
                        if "avatar" in fb_res.media:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Avatar     : {A.BLUE}{fb_res.media['avatar']}{A.RESET}")
                    else:
                        print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Status     : {A.GRAY}Tidak Terdaftar / Error ({fb_res.get_reason()}){A.RESET}")

                    print()

                    # 4. Tampilkan hasil IG
                    print(f"  {A.PINK}{A.BOLD}INSTAGRAM{A.RESET}")
                    if ig_res.is_found():
                        print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Status     : {A.GREEN}{A.BOLD}Terdaftar{A.RESET}")
                        if "name" in ig_res.extra:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Nama       : {ig_res.extra['name']}{A.RESET}")
                        if "recovery_method" in ig_res.extra:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Recovery   : {ig_res.extra['recovery_method']}{A.RESET}")
                        if "avatar" in ig_res.media:
                            print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Avatar     : {A.BLUE}{ig_res.media['avatar']}{A.RESET}")
                    else:
                        print(f"  {A.CYAN}▸{A.RESET} {A.WHITE}Status     : {A.GRAY}Tidak Terdaftar / Error ({ig_res.get_reason()}){A.RESET}")

                    print(f"\n  {A.PURPLE}{'─'*48}{A.RESET}\n")

                except Exception as e:
                    print(f"  {A.GRAY}Gagal memindai: {e}{A.RESET}\n")
                continue
            # ---------------------------

            # Blok ini HANYA akan tereksekusi oleh menu GTC
            args = build_parser().parse_args()
            print_startup(args)
            return args.func(args)

        except GtcError as e:
            print(f"  {A.GRAY}Error: {e}{A.RESET}\n")
        except Exception as e:
            print(f"  {A.GRAY}Unexpected error: {e}{A.RESET}\n")


def main() -> int:
    if len(sys.argv) == 1:
        return interactive()
    parser = build_parser()
    args = parser.parse_args()
    print_startup(args)
    try:
        return args.func(args)
    except GtcError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
