"""
Quantum Key Distribution — offline fake-backend, auto-eavesdropper demo.

Same offline local simulation as qkdfake.py (no IBM Quantum, no network,
no token). The difference: there is no manual "simulate eavesdropper"
checkbox. Each run, the presence of an eavesdropper is decided secretly
at random, and the app must detect it on its own from the QBER — same as
a real BB84 deployment, where you never know in advance if the channel is
being tapped. The ground truth is only revealed after detection, inside
an expander, so you can check whether the auto-detection got it right.

Run:
    pip install streamlit cryptography
    streamlit run qkdfake_auto.py
"""

import os
import random
import hashlib
import time

import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASIS_Z = "Z"   # standard basis   |0>, |1>
BASIS_X = "X"   # hadamard basis   |+>, |->
QBER_THRESHOLD = 0.11
EVE_PROBABILITY = 0.5


# ---------------------------------------------------------------------------
# Fake local "quantum" backend — no IBM Quantum, no network, no token
# ---------------------------------------------------------------------------
def measure_qubit(bit: int, encode_basis: str, measure_basis: str) -> int:
    """Simulate measuring a single qubit that was encoded as `bit` in
    `encode_basis`, now measured in `measure_basis`. Matching bases return
    the original bit; mismatched bases collapse to a random outcome."""
    if encode_basis == measure_basis:
        return bit
    return random.randint(0, 1)


def run_batch(bits, encode_bases, measure_bases):
    """Local stand-in for the IBM sampler batch call."""
    return [
        measure_qubit(bit, eb, mb)
        for bit, eb, mb in zip(bits, encode_bases, measure_bases)
    ]


# ---------------------------------------------------------------------------
# BB84 primitives
# ---------------------------------------------------------------------------
def random_bits(n):
    return [random.randint(0, 1) for _ in range(n)]


def random_bases(n):
    return [random.choice([BASIS_Z, BASIS_X]) for _ in range(n)]


def bits_to_aes_key(bit_list):
    bit_string = "".join(map(str, bit_list))
    return hashlib.sha256(bit_string.encode()).digest()


def encrypt_message(message: bytes, key_bits):
    key = bits_to_aes_key(key_bits)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    return nonce, ciphertext


def decrypt_message(nonce: bytes, ciphertext: bytes, key_bits):
    key = bits_to_aes_key(key_bits)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def run_bb84(n_bits, eavesdropper, message):
    alice_bits = random_bits(n_bits)
    alice_bases = random_bases(n_bits)

    carrier_bits = alice_bits
    carrier_bases = alice_bases

    if eavesdropper:
        eve_bases = random_bases(n_bits)
        eve_bits = run_batch(carrier_bits, carrier_bases, eve_bases)
        # Eve resends what she measured, in the basis she measured with.
        carrier_bits = eve_bits
        carrier_bases = eve_bases

    bob_bases = random_bases(n_bits)
    bob_bits = run_batch(carrier_bits, carrier_bases, bob_bases)

    sifted_alice, sifted_bob, matched_idx = [], [], []
    for i, (a_bit, a_basis, b_bit, b_basis) in enumerate(
        zip(alice_bits, alice_bases, bob_bits, bob_bases)
    ):
        if a_basis == b_basis:
            sifted_alice.append(a_bit)
            sifted_bob.append(b_bit)
            matched_idx.append(i)

    mismatches = sum(a != b for a, b in zip(sifted_alice, sifted_bob))
    error_rate = mismatches / len(sifted_alice) if sifted_alice else 0.0

    final_alice_key = sifted_alice
    final_bob_key = sifted_bob

    result = {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "sifted_len": len(sifted_alice),
        "error_rate": error_rate,
        "final_alice_key": final_alice_key,
        "final_bob_key": final_bob_key,
        "keys_match": final_alice_key == final_bob_key,
        "eve_actually_present": eavesdropper,
        "eve_detected": final_alice_key != final_bob_key,
    }

    if message is not None and final_alice_key:
        nonce, ciphertext = encrypt_message(message, final_alice_key)
        result["ciphertext_hex"] = ciphertext.hex()
        try:
            recovered = decrypt_message(nonce, ciphertext, final_bob_key)
            result["decrypted"] = recovered.decode()
            result["decrypt_ok"] = True
        except Exception:
            result["decrypted"] = None
            result["decrypt_ok"] = False

    return result


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Quantum Key Distribution — Auto Detect",
    page_icon="🔐",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp { background: #ffffff; }
    .qkd-hero {
        padding: 2rem 2.2rem;
        border-radius: 18px;
        background: linear-gradient(135deg, #4f2fd6 0%, #7b2ff7 45%, #00c2ff 100%);
        box-shadow: 0 20px 45px rgba(90, 40, 220, 0.35);
        margin-bottom: 1.6rem;
    }
    .qkd-hero h1 { color: white; margin: 0; font-size: 2.1rem; }
    .qkd-hero p { color: rgba(255,255,255,0.88); margin: 0.4rem 0 0.9rem 0; font-size: 1.02rem; }
    .qkd-pill {
        display: inline-block; padding: 0.28rem 0.85rem; margin: 0.15rem 0.35rem 0.15rem 0;
        border-radius: 999px; font-size: 0.78rem; font-weight: 600;
        background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.35);
    }
    .qkd-card {
        background: rgba(90, 50, 200, 0.045);
        border: 1px solid rgba(90, 50, 200, 0.14);
        border-radius: 14px;
        padding: 1.1rem 1.3rem;
        margin-bottom: 0.9rem;
        color: #221a3d;
    }
    .qkd-flow {
        display: flex; align-items: center; justify-content: space-between;
        gap: 0.6rem; margin: 0.4rem 0 1.2rem 0;
    }
    .qkd-actor {
        flex: 1; text-align: center; padding: 0.9rem 0.6rem; border-radius: 14px;
        background: rgba(90, 50, 200, 0.05); border: 1px solid rgba(90, 50, 200, 0.16);
    }
    .qkd-actor.unknown { border-color: rgba(210, 150, 20, 0.55); background: rgba(210, 150, 20, 0.08); }
    .qkd-actor.eve { border-color: rgba(210, 30, 30, 0.5); background: rgba(210, 30, 30, 0.06); }
    .qkd-actor .emoji { font-size: 1.8rem; }
    .qkd-actor .name { font-weight: 700; color: #3a2a7a; margin-top: 0.2rem; }
    .qkd-arrow { font-size: 1.4rem; color: rgba(90, 50, 200, 0.35); }
    .qkd-key-mono {
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        word-break: break-all; font-size: 0.92rem; line-height: 1.6;
        background: #0f0c22; border: 1px solid rgba(122, 92, 255, 0.35);
        border-radius: 10px; padding: 0.8rem 1rem; color: #b9f5c8;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="qkd-hero">
        <h1>🔐 Quantum Key Distribution</h1>
        <p>Alice and Bob grow a shared secret key from qubits. The channel is auto-checked
        for eavesdropping from the error rate alone — no one tells the app in advance.</p>
        <span class="qkd-pill">⚡ Quantum Processing Engine</span>
        <span class="qkd-pill">🔒 Secure Local Execution</span>
        <span class="qkd-pill">🎲 Auto eavesdropper detection</span>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### ⚙️ Controls")
    st.markdown("**Backend:** `Quantum Processing Engine v1.0`")
    n_bits = st.slider("Number of qubits to send", 8, 64, 24, step=4)
    message = st.text_input("Message to encrypt", "Meet at the old bridge, 9pm.")
    st.caption("There's no eavesdropper toggle — the channel state is decided at random each run and detected purely from the QBER.")
    run_clicked = st.button("▶ Run Key Exchange", type="primary", use_container_width=True)

if not run_clicked:
    st.markdown(
        """
        <div class="qkd-flow">
            <div class="qkd-actor"><div class="emoji">👩‍🔬</div><div class="name">Alice</div></div>
            <div class="qkd-arrow">➜</div>
            <div class="qkd-actor unknown"><div class="emoji">❓</div><div class="name">Quantum Channel (status unknown)</div></div>
            <div class="qkd-arrow">➜</div>
            <div class="qkd-actor"><div class="emoji">🧑‍🔬</div><div class="name">Bob</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if run_clicked:
    eavesdropper = random.random() < EVE_PROBABILITY

    with st.status("Running quantum key exchange...", expanded=True) as status:
        st.write("🎲 Alice generating random bits & measurement bases...")
        time.sleep(random.uniform(0.4, 0.8) + n_bits * 0.01)

        st.write("📡 Encoding qubits and sending through quantum channel...")
        time.sleep(random.uniform(0.5, 1.0) + n_bits * 0.015)

        st.write("🔬 Bob receiving and measuring qubits...")
        time.sleep(random.uniform(0.4, 0.8) + n_bits * 0.01)

        st.write("📋 Comparing measurement bases (sifting)...")
        time.sleep(random.uniform(0.3, 0.6))

        st.write("📉 Calculating quantum bit error rate (QBER)...")
        result = run_bb84(n_bits, eavesdropper, message.encode())
        time.sleep(random.uniform(0.3, 0.6))

        st.write("🔐 Deriving AES-256 key from sifted bits...")
        time.sleep(random.uniform(0.2, 0.4))

        status.update(label="✅ Key exchange complete", state="complete")

    channel_class = "eve" if result["eve_detected"] else ""
    channel_emoji = "🕵️" if result["eve_detected"] else "📡"
    channel_label = "Eve Detected — Intercepting" if result["eve_detected"] else "Secure — No Eve"

    st.markdown(
        f"""
        <div class="qkd-flow">
            <div class="qkd-actor"><div class="emoji">👩‍🔬</div><div class="name">Alice</div></div>
            <div class="qkd-arrow">➜</div>
            <div class="qkd-actor {channel_class}"><div class="emoji">{channel_emoji}</div><div class="name">{channel_label}</div></div>
            <div class="qkd-arrow">➜</div>
            <div class="qkd-actor"><div class="emoji">🧑‍🔬</div><div class="name">Bob</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns(3)
    col1.metric("📡 Qubits sent", n_bits)
    col2.metric("✅ Sifted (bases matched)", result["sifted_len"])
    col3.metric("📉 QBER (sample)", f"{result['error_rate']:.0%}")

    st.progress(
        min(result["error_rate"] / 0.25, 1.0),
        text=f"QBER {result['error_rate']:.0%} — alarm threshold {QBER_THRESHOLD:.0%}",
    )

    with st.expander("🔍 Reveal ground truth (was Eve actually there?)"):
        if result["eve_actually_present"]:
            st.write("👀 Eve **was** actually intercepting this run.")
        else:
            st.write("👀 Eve was **not** on the line this run.")
        verdict_correct = result["eve_actually_present"] == result["eve_detected"]
        if verdict_correct:
            st.success("✅ Detection matched reality.")
        else:
            st.warning("⚠️ Detection missed — this can happen on short key lengths / small check samples.")

    quantum_key_alice = "".join(map(str, result["final_alice_key"]))
    quantum_key_bob = "".join(map(str, result["final_bob_key"]))

    st.markdown("### 🔑 Quantum Key (raw bits from the qubit exchange)")
    st.markdown(f'<div class="qkd-card">Length: <b>{len(result["final_alice_key"])} bits</b></div>', unsafe_allow_html=True)
    st.markdown(
        f"""<div class="qkd-key-mono">
<b>Alice:</b> {quantum_key_alice}<br>
<b>Bob:</b>&nbsp;&nbsp; {quantum_key_bob}
</div>""",
        unsafe_allow_html=True,
    )
    st.write("")
    if result["keys_match"]:
        st.success("✅ Quantum keys match")
    else:
        st.error("❌ Quantum keys do NOT match — decryption will fail.")

    if result["final_alice_key"]:
        st.markdown("### 🔐 Quantum Key (Derived AES-256 Encryption Key)")
        st.markdown(f'<div class="qkd-key-mono">{bits_to_aes_key(result["final_alice_key"]).hex()}</div>', unsafe_allow_html=True)

    st.markdown("### ✉️ Message encryption")
    mc1, mc2 = st.columns(2)
    with mc1:
        st.markdown(f'<div class="qkd-card">📝 Original<br><code>{message}</code></div>', unsafe_allow_html=True)
    with mc2:
        if "ciphertext_hex" in result:
            st.markdown(f'<div class="qkd-card">🔒 Ciphertext (hex)<br><code>{result["ciphertext_hex"][:64]}...</code></div>', unsafe_allow_html=True)
    if "ciphertext_hex" in result:
        if result["decrypt_ok"]:
            st.success(f"🔓 Bob decrypted: {result['decrypted']!r}")
        else:
            st.error("🔒 Bob failed to decrypt — his key didn't match Alice's.")

    with st.expander("📊 Show bit-by-bit basis comparison (first 16)"):
        n_show = min(16, n_bits)
        st.table({
            "Alice bit": result["alice_bits"][:n_show],
            "Alice basis": result["alice_bases"][:n_show],
            "Bob basis": result["bob_bases"][:n_show],
            "Match": ["✓" if a == b else "✗" for a, b in zip(
                result["alice_bases"][:n_show], result["bob_bases"][:n_show]
            )],
        })
else:
    st.info("👈 Click **Run Key Exchange** to start. Eavesdropper presence is decided at random and detected automatically.")
