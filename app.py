"""
app.py - Streamlit Replay Attack Demo (with left-side navigation)
Features:
 - Left-side navigation (sidebar) with buttons (radio) to open sections:
   Vulnerable Flow, Protected Flow, Attacker Vault, Demo Code, Step-by-Step
 - Cleaner, slightly improved UI layout and helpful messages
 - Safe st.secrets usage with local fallback
 - All logic in a single file for easy deployment
"""

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
# Use st.secrets if available (deployment); otherwise use a local fallback.
try:
    SECRET_KEY = st.secrets["secret_key"]
except Exception:
    SECRET_KEY = "local_demo_secret_please_change"

DEFAULT_PROTECTED_TTL = 30  # seconds

# -------------------------
# Helper functions
# -------------------------
def b64_encode(obj: dict) -> str:
    """Base64 (URL-safe) encode a JSON object."""
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()


def b64_decode(token: str):
    """Decode a base64 JSON token; return dict or None."""
    try:
        return json.loads(base64.urlsafe_b64decode(token.encode()).decode())
    except Exception:
        return None


def hmac_sign_bytes(payload_bytes: bytes) -> str:
    """Return HMAC-SHA256 hex signature for bytes using SECRET_KEY."""
    return hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()


def sign_payload(payload: dict) -> str:
    """Return HMAC signature for a JSON-serializable payload (stable key order)."""
    b = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hmac_sign_bytes(b)


# -------------------------
# Session state init
# -------------------------
if "attacker_vault" not in st.session_state:
    st.session_state.attacker_vault = []  # list of dicts: {type, token, sig?, captured_at}
if "used_nonces" not in st.session_state:
    st.session_state.used_nonces = set()
if "last_vuln_token" not in st.session_state:
    st.session_state.last_vuln_token = None
if "last_prot_token" not in st.session_state:
    st.session_state.last_prot_token = None
if "protected_ttl" not in st.session_state:
    st.session_state.protected_ttl = DEFAULT_PROTECTED_TTL
if "nav" not in st.session_state:
    st.session_state.nav = "Vulnerable Flow"

# -------------------------
# LEFT-SIDE NAVIGATION (buttons via radio)
# -------------------------
st.sidebar.title("Navigate")
section = st.sidebar.radio(
    "Open section",
    ("Vulnerable Flow", "Protected Flow", "Attacker Vault", "Demo Code", "Step-by-Step"),
    index=("Vulnerable Flow", "Protected Flow", "Attacker Vault", "Demo Code", "Step-by-Step").index(
        st.session_state.get("nav", "Vulnerable Flow")
    ),
)
st.session_state.nav = section

# Small utility block on sidebar
st.sidebar.markdown("---")
st.sidebar.markdown("**Quick actions**")
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
st.sidebar.caption("Secret key used for HMAC is read from Streamlit secrets or falls back to a local value.\nChange in `.streamlit/secrets.toml` for production.")

# -------------------------
# Page Top: title + short intro
# -------------------------
st.title("Replay Attack — Demonstration & Prevention")
st.write(
    "An educational demo showing a vulnerable token flow (replayable) and a protected flow "
    "that uses `nonce`, `timestamp`, and an HMAC `signature` to prevent replay attacks."
)
st.markdown("---")

# -------------------------
# SECTION: Vulnerable Flow
# -------------------------
def show_vulnerable_flow():
    st.header("Vulnerable Flow")
    st.info(
        "This flow demonstrates a naive token issuance where the token is simply a base64-encoded JSON "
        "payload (username + issued-at). There is no signature or nonce — so captured tokens can be replayed."
    )

    col_main, col_side = st.columns([3, 1])
    with col_main:
        username_vuln = st.text_input("Username (vulnerable)", value="alice", key="uname_vuln_sec")
        if st.button("Issue vulnerable token"):
            payload = {"user": username_vuln, "iat": int(time.time())}
            token = b64_encode(payload)
            st.session_state.last_vuln_token = token
            st.success("Vulnerable token issued.")
            st.code(token, language="text")

        st.markdown("**Attacker actions (simulate sniffing and replay):**")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Capture last vulnerable token"):
                tok = st.session_state.last_vuln_token
                if not tok:
                    st.warning("No vulnerable token to capture. Issue a token first.")
                else:
                    st.session_state.attacker_vault.append(
                        {"type": "vulnerable", "token": tok, "captured_at": int(time.time())}
                    )
                    st.success("Token captured to attacker vault.")
        with c2:
            if st.button("Replay captured vulnerable token"):
                entry = next((e for e in st.session_state.attacker_vault if e.get("type") == "vulnerable"), None)
                if not entry:
                    st.warning("No vulnerable token in attacker vault.")
                else:
                    decoded = b64_decode(entry["token"])
                    if decoded:
                        st.error("⚠️ REPLAY SUCCEEDED — naive server accepted the token!")
                        st.json(decoded)
                    else:
                        st.error("Malformed token — replay failed.")

    with col_side:
        st.markdown("**Why this is bad**")
        st.write("- Token is unsigned and replayable.")
        st.write("- An attacker who sees the token can impersonate the user.")
        st.write("- No server-side checks for freshness or uniqueness.")

# -------------------------
# SECTION: Protected Flow
# -------------------------
def show_protected_flow():
    st.header("Protected Flow")
    st.success("This flow demonstrates protections: nonce + timestamp + HMAC signature.")
    st.write(
        "Server issues a payload `{user, nonce, ts}` and an HMAC-SHA256 signature computed over a stable JSON encoding. "
        "On replay the server validates signature, checks freshness (TTL), and ensures the nonce was not used before."
    )

    col_main, col_side = st.columns([3, 1])
    with col_main:
        ttl = st.number_input(
            "Protected token TTL (seconds) — freshness window",
            min_value=5,
            max_value=3600,
            value=st.session_state.protected_ttl,
            step=5,
            key="ttl_input_main",
        )
        st.session_state.protected_ttl = ttl

        username_prot = st.text_input("Username (protected)", value="bob", key="uname_prot_sec")

        if st.button("Get protected token (issue nonce & signature)"):
            nonce = secrets.token_hex(8)
            ts = int(time.time())
            payload = {"user": username_prot, "nonce": nonce, "ts": ts}
            payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            signature = hmac_sign_bytes(payload_bytes)
            token = base64.urlsafe_b64encode(payload_bytes).decode()
            st.session_state.last_prot_token = {"token": token, "signature": signature, "payload": payload}
            st.success("Protected token issued.")
            st.code(json.dumps({"token": token, "signature": signature}, indent=2), language="json")

        st.markdown("**Attacker actions (capture & replay)**")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Capture last protected token"):
                tokobj = st.session_state.last_prot_token
                if not tokobj:
                    st.warning("No protected token to capture. Request a token first.")
                else:
                    st.session_state.attacker_vault.append(
                        {"type": "protected", "token": tokobj["token"], "sig": tokobj["signature"], "captured_at": int(time.time())}
                    )
                    st.success("Protected token + signature captured.")
        with c2:
            if st.button("Replay captured protected token"):
                entry = next((e for e in st.session_state.attacker_vault if e.get("type") == "protected"), None)
                if not entry:
                    st.warning("No protected token in attacker vault.")
                else:
                    payload = b64_decode(entry["token"])
                    provided_sig = entry.get("sig")
                    now = int(time.time())

                    if payload is None:
                        st.error("Token format invalid.")
                    else:
                        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
                        expected_sig = hmac_sign_bytes(payload_bytes)

                        if not hmac.compare_digest(expected_sig, provided_sig):
                            st.error("🚫 REPLAY BLOCKED — signature mismatch.")
                        elif abs(now - int(payload.get("ts", 0))) > st.session_state.protected_ttl:
                            st.error("🚫 REPLAY BLOCKED — timestamp expired or outside allowed window.")
                        elif payload.get("nonce") in st.session_state.used_nonces:
                            st.error("🚫 REPLAY BLOCKED — nonce already used (replay detected).")
                        else:
                            # Accept and mark nonce used
                            st.session_state.used_nonces.add(payload.get("nonce"))
                            st.success(f"✅ Token accepted for user `{payload.get('user')}` (first-time use).")
                            st.json(payload)

    with col_side:
        st.markdown("**Protection summary**")
        st.write(f"- TTL (freshness window): **{st.session_state.protected_ttl}** seconds")
        st.write("- Signature: HMAC-SHA256 over stable JSON bytes.")
        st.write("- Nonce uniqueness: server tracks used nonces and rejects reuse.")

# -------------------------
# SECTION: Attacker Vault & Server State
# -------------------------
def show_attacker_vault():
    st.header("Attacker Vault & Server State")
    st.write("View captured tokens and server state (used nonces). Use the quick actions on the left to clear state.")

    if st.session_state.attacker_vault:
        rows = []
        for i, e in enumerate(st.session_state.attacker_vault, 1):
            typ = e.get("type")
            cap = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("captured_at", 0)))
            preview = ""
            if typ == "vulnerable":
                tok = e.get("token", "")
                preview = tok[:80] + ("..." if len(tok) > 80 else "")
            else:
                preview = e.get("sig", "")[:80] + ("..." if len(e.get("sig", "")) > 80 else "")
            rows.append({"#": i, "type": typ, "captured_at": cap, "preview": preview})
        st.table(rows)
    else:
        st.info("No tokens captured yet. Use the capture buttons in other sections.")

    st.markdown("-")
    st.write(f"Used nonces count: **{len(st.session_state.used_nonces)}**")
    if st.session_state.used_nonces:
        st.write("Sample nonces (first 10):", list(st.session_state.used_nonces)[:10])

# -------------------------
# SECTION: Demo Code (explainable)
# -------------------------
def show_demo_code():
    st.header("Demo Code — How it works (explain to users)")
    st.markdown(
        "Below are compact, copyable code snippets that demonstrate the key ideas you can show to learners."
    )

    demo_make_vulnerable = '''def make_vulnerable_token(username: str) -> str:
    # naive token: just username + issued-at (no signature)
    payload = {"user": username, "iat": int(time.time())}
    token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    return token
'''

    demo_make_protected = '''def make_protected_token(username: str) -> dict:
    nonce = secrets.token_hex(8)
    ts = int(time.time())
    payload = {"user": username, "nonce": nonce, "ts": ts}
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(payload_bytes).decode()
    return {"token": token, "signature": signature, "payload": payload}
'''

    demo_verify_protected = '''def verify_protected_token(token_b64: str, signature: str, max_age_sec: int) -> (bool, str):
    # decode
    try:
        payload_bytes = base64.urlsafe_b64decode(token_b64.encode())
        payload = json.loads(payload_bytes.decode())
    except Exception:
        return False, "invalid token format"

    # signature
    expected_sig = hmac.new(SECRET_KEY.encode(), json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        return False, "signature mismatch"

    # freshness
    now = int(time.time())
    if abs(now - int(payload.get("ts", 0))) > max_age_sec:
        return False, "timestamp expired"

    # nonce uniqueness (server must track used nonces)
    nonce = payload.get("nonce")
    if nonce in used_nonces:
        return False, "nonce already used (replay detected)"

    used_nonces.add(nonce)
    return True, f"welcome {payload.get('user')}"
'''

    st.subheader("Make vulnerable token")
    st.code(demo_make_vulnerable, language="python")

    st.subheader("Make protected token (nonce + ts + HMAC)")
    st.code(demo_make_protected, language="python")

    st.subheader("Verify protected token (server checks signature, freshness, nonce uniqueness)")
    st.code(demo_verify_protected, language="python")

    st.markdown(
        """
**Talk track bullets**
- Vulnerable token: unsigned and replayable.
- Protected token: signature proves server origin, timestamp ensures freshness, nonce ensures single-use.
- In production: use TLS, rotate keys, consider asymmetric signatures or OAuth/JWT with short ttl, and store nonces in a durable store when running multiple servers.
"""
    )

# -------------------------
# SECTION: Step-by-step guide
# -------------------------
def show_step_by_step():
    st.header("Step-by-step guide — How to demo this to others")
    with st.expander("Open step-by-step instructions"):
        st.markdown(
            """
1. Vulnerable flow:
   - Issue a vulnerable token for a username.
   - Capture it (simulate network sniff).
   - Replay it: the naive server will accept (demonstrate REPLAY SUCCEEDED).

2. Protected flow:
   - Issue a protected token (server attaches nonce, ts, and signature).
   - Capture the token+signature.
   - Replay it immediately: server verifies signature & freshness and will accept on first use.
   - Replay again: server rejects because the nonce is already used.
   - Wait longer than the TTL and attempt replay: server rejects due to timestamp expiration.

3. Experiments:
   - Change TTL in the protected flow and show how expiry behaves.
   - Show what happens if signature bytes are tampered with (modify signature in attacker vault).
   - Explain how the server must persist used nonces for multi-instance setups.

4. Notes:
   - This demo stores nonces in session-state (ephemeral). For real systems, store used nonces or short-lived token records in a shared DB or cache (Redis).
"""
        )

# -------------------------
# Render the selected section
# -------------------------
if st.session_state.nav == "Vulnerable Flow":
    show_vulnerable_flow()
elif st.session_state.nav == "Protected Flow":
    show_protected_flow()
elif st.session_state.nav == "Attacker Vault":
    show_attacker_vault()
elif st.session_state.nav == "Demo Code":
    show_demo_code()
elif st.session_state.nav == "Step-by-Step":
    show_step_by_step()

st.markdown("---")
st.caption("Educational demo. Do not use this exact token design in production without security reviews.")
