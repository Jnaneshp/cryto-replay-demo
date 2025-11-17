# Updated Replay Attack Demo with Introduction, Objectives, and Conclusion Sections
# (Full Streamlit code)

# NOTE TO USER:
# This file includes three new sections added to the UI:
# - Introduction
# - Objectives
# - Conclusion
# These appear as additional navigation options on the sidebar.

import streamlit as st
import time
import base64
import json
import hmac
import hashlib
import secrets
import uuid

# Page config
st.set_page_config(page_title="Replay Attack Demo", layout="wide", initial_sidebar_state="expanded")

# -------------------------
# Secrets / Configuration
# -------------------------
try:
    SECRET_KEY = st.secrets["secret_key"]
except Exception:
    SECRET_KEY = "local_demo_secret_please_change"

DEFAULT_PROTECTED_TTL = 30

# -------------------------
# Helper functions
# -------------------------
def b64_encode(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()

def b64_decode(token: str):
    try:
        return json.loads(base64.urlsafe_b64decode(token.encode()).decode())
    except Exception:
        return None

def hmac_sign_bytes(payload_bytes: bytes) -> str:
    return hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()

def sign_payload(payload: dict) -> str:
    b = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hmac_sign_bytes(b)

# -------------------------
# Session state initialization
# -------------------------
if "attacker_vault" not in st.session_state:
    st.session_state.attacker_vault = []
if "used_nonces" not in st.session_state:
    st.session_state.used_nonces = set()
if "last_vuln_token" not in st.session_state:
    st.session_state.last_vuln_token = None
if "last_prot_token" not in st.session_state:
    st.session_state.last_prot_token = None
if "protected_ttl" not in st.session_state:
    st.session_state.protected_ttl = DEFAULT_PROTECTED_TTL
if "nav" not in st.session_state:
    st.session_state.nav = "Introduction"

# -------------------------
# LEFT-SIDE NAVIGATION
# -------------------------
st.sidebar.title("Navigate")
navigation_options = (
    "Introduction",
    "Objectives",
    "Vulnerable Flow",
    "Protected Flow",
    "Attacker Vault",
    "Demo Code",
    "Step-by-Step",
    "Conclusion",
)

section = st.sidebar.radio("Open section", navigation_options, index=navigation_options.index(st.session_state.nav))
st.session_state.nav = section

st.sidebar.markdown("---")
st.sidebar.markdown("**Quick Actions**")
if st.sidebar.button("Reset demo (clear state)"):
    st.session_state.last_vuln_token = None
    st.session_state.last_prot_token = None
    st.session_state.attacker_vault = []
    st.session_state.used_nonces = set()
    st.success("Demo state reset.")
if st.sidebar.button("Clear attacker vault"):
    st.session_state.attacker_vault = []
    st.success("Attacker vault cleared.")
if st.sidebar.button("Clear used nonces"):
    st.session_state.used_nonces = set()
    st.success("Used nonces cleared.")

st.sidebar.markdown("---")
st.sidebar.caption("Secret key used for HMAC is read from Streamlit secrets or falls back to a local value.")

# -------------------------
# GLOBAL TITLE
# -------------------------
st.title("Replay Attack — Demonstration & Prevention")
st.markdown("---")

# -------------------------
# NEW SECTION — INTRODUCTION
# -------------------------
def show_introduction():
    st.header("Introduction")
    st.write(
        "Replay attacks occur when an attacker captures a valid request or token and replays it to a server to gain unauthorized access.\n"
        "This demo teaches how naive token designs can be exploited and how adding nonce, timestamps, and signatures prevents replay attacks."
    )
    st.write("It is fully interactive — test vulnerable and protected flows to understand the difference clearly.")

# -------------------------
# NEW SECTION — OBJECTIVES
# -------------------------
def show_objectives():
    st.header("Objectives of This Demo")
    st.markdown(
        """
        This demonstration aims to:
        
        - Show how **vulnerable tokens** can be easily captured and replayed.
        - Demonstrate a secure design using **nonce**, **timestamp**, and **HMAC signatures**.
        - Provide hands‑on interaction to help beginners understand secure token validation.
        - Highlight why replay protection is critical in authentication and API security.
        - Educate learners on how to simulate attacker behavior and server-side validation.
        """
    )

# -------------------------
# SECTION — Vulnerable Flow
# -------------------------
def show_vulnerable_flow():
    st.header("Vulnerable Flow")
    st.info(
        "A naive token flow: the token is just base64‑encoded JSON. No signature, no freshness, no nonce.\n"
        "Anyone capturing it can replay it and impersonate the user."
    )

    col_main, col_side = st.columns([3,1])
    with col_main:
        username = st.text_input("Username (vulnerable)", value="alice")
        if st.button("Issue vulnerable token"):
            payload = {"user": username, "iat": int(time.time())}
            token = b64_encode(payload)
            st.session_state.last_vuln_token = token
            st.success("Vulnerable token issued.")
            st.code(token, language="text")

        st.subheader("Attacker simulation")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Capture last vulnerable token"):
                tok = st.session_state.last_vuln_token
                if not tok:
                    st.warning("No token available.")
                else:
                    st.session_state.attacker_vault.append({
                        "type": "vulnerable", "token": tok, "captured_at": int(time.time())
                    })
                    st.success("Captured.")
        with c2:
            if st.button("Replay captured vulnerable token"):
                entry = next((e for e in st.session_state.attacker_vault if e["type"]=="vulnerable"), None)
                if not entry:
                    st.warning("Nothing to replay.")
                else:
                    decoded = b64_decode(entry["token"])
                    if decoded:
                        st.error("⚠️ Replay Succeeded — Server accepted the token!")
                        st.json(decoded)
                    else:
                        st.error("Invalid token.")

    with col_side:
        st.markdown("**Why this is insecure**")
        st.write("- No signature")
        st.write("- No freshness check")
        st.write("- Fully replayable")

# -------------------------
# SECTION — Protected Flow
# -------------------------
def show_protected_flow():
    st.header("Protected Flow — Secure Token Design")
    st.success("This design includes nonce + timestamp + HMAC signature.")

    col_main, col_side = st.columns([3,1])
    with col_main:
        ttl = st.number_input(
            "Token TTL (seconds)", min_value=5, max_value=3600,
            value=st.session_state.protected_ttl, step=5
        )
        st.session_state.protected_ttl = ttl

        username = st.text_input("Username (protected)", value="bob")

        if st.button("Issue protected token"):
            nonce = secrets.token_hex(8)
            ts = int(time.time())
            payload = {"user": username, "nonce": nonce, "ts": ts}
            payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            signature = hmac_sign_bytes(payload_bytes)
            token = base64.urlsafe_b64encode(payload_bytes).decode()
            st.session_state.last_prot_token = {"token": token, "signature": signature, "payload": payload}
            st.success("Protected token issued.")
            st.code(json.dumps({"token": token, "signature": signature}, indent=2))

        st.subheader("Attacker simulation")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Capture protected token"):
                tokobj = st.session_state.last_prot_token
                if not tokobj:
                    st.warning("No token issued yet.")
                else:
                    st.session_state.attacker_vault.append({
                        "type": "protected", "token": tokobj["token"],
                        "sig": tokobj["signature"], "captured_at": int(time.time())
                    })
                    st.success("Captured protected token.")
        with c2:
            if st.button("Replay protected token"):
                entry = next((e for e in st.session_state.attacker_vault if e["type"]=="protected"), None)
                if not entry:
                    st.warning("Nothing to replay.")
                else:
                    payload = b64_decode(entry["token"])
                    provided_sig = entry["sig"]
                    now = int(time.time())

                    if payload is None:
                        st.error("Invalid token format.")
                        return

                    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
                    expected_sig = hmac_sign_bytes(payload_bytes)

                    if not hmac.compare_digest(expected_sig, provided_sig):
                        st.error("🚫 Replay Blocked — Signature mismatch.")
                    elif abs(now - payload.get("ts", 0)) > st.session_state.protected_ttl:
                        st.error("🚫 Replay Blocked — Token expired.")
                    elif payload.get("nonce") in st.session_state.used_nonces:
                        st.error("🚫 Replay Blocked — Nonce already used.")
                    else:
                        st.session_state.used_nonces.add(payload["nonce"])
                        st.success(f"✅ Token accepted for user {payload['user']}")
                        st.json(payload)

    with col_side:
        st.markdown("**Security Summary**")
        st.write("- HMAC signature ensures authenticity")
        st.write("- Nonce prevents reuse")
        st.write(f"- TTL = {st.session_state.protected_ttl}s ensures freshness")

# -------------------------
# SECTION — Attacker Vault
# -------------------------
def show_attacker_vault():
    st.header("Attacker Vault & Server State")

    if st.session_state.attacker_vault:
        rows = []
        for i, e in enumerate(st.session_state.attacker_vault, 1):
            preview = e.get("token", "")[0:60] + "..."
            rows.append({"#": i, "type": e["type"], "captured_at": time.ctime(e["captured_at"]), "preview": preview})
        st.table(rows)
    else:
        st.info("Vault is empty.")

    st.write(f"Used nonces: {len(st.session_state.used_nonces)}")

# -------------------------
# SECTION — Demo Code Snippets
# -------------------------
def show_demo_code():
    st.header("Demo Code Snippets")
    st.write("Use these small, easy examples to explain concepts to learners.")

    st.subheader("Vulnerable Token Code")
    st.code(
        """def make_vulnerable_token(username):
    payload = {"user": username, "iat": int(time.time())}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
"""
    )

    st.subheader("Protected Token Code")
    st.code(
        """def make_protected_token(username):
    nonce = secrets.token_hex(8)
    ts = int(time.time())
    payload = {"user": username, "nonce": nonce, "ts": ts}
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(payload_bytes).decode()
    return {"token": token, "signature": signature}
"""
    )

# -------------------------
# SECTION — Step-by-Step Guide
# -------------------------
def show_step_by_step():
    st.header("Step-by-Step Guide")
    st.write("Follow these steps when presenting to others.")
    st.markdown(
        """
1. Issue a vulnerable token → capture → replay → see replay success.
2. Issue a protected token → capture → replay:
   - First replay: accepted
   - Second replay: blocked (nonce used)
3. Wait beyond TTL → replay → blocked (expired)
4. Modify signature → replay → blocked (signature mismatch)
"""
    )

# -------------------------
# NEW SECTION — CONCLUSION
# -------------------------
def show_conclusion():
    st.header("Conclusion")
    st.write(
        "This demo shows how vulnerable token designs can be exploited using replay attacks."
        " By adding cryptographic signatures, freshness checks, and nonce-based uniqueness, "
        "we can fully prevent replay attempts."
    )
    st.write(
        "Understanding these concepts is essential for building secure authentication systems, "
        "APIs, and real‑world production applications."
    )

# -------------------------
# RENDER SECTION
# -------------------------
if section == "Introduction":
    show_introduction()
elif section == "Objectives":
    show_objectives()
elif section == "Vulnerable Flow":
    show_vulnerable_flow()
elif section == "Protected Flow":
    show_protected_flow()
elif section == "Attacker Vault":
    show_attacker_vault()
elif section == "Demo Code":
    show_demo_code()
elif section == "Step-by-Step":
    show_step_by_step()
elif section == "Conclusion":
    show_conclusion()

st.markdown("---")
st.caption("Educational demo. Not for production use.")
