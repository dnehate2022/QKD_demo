"""
BB84 Quantum Key Distribution — Streamlit demo.

Wraps the BB84 circuit logic in an interactive UI. By default this runs on
the local Aer simulator (no account needed). To run on real IBM Quantum
hardware instead, set an environment variable BEFORE launching streamlit —
never hardcode a token in this file:

    Windows (PowerShell):  setx IBM_QUANTUM_TOKEN "your-44-char-token"
    Mac/Linux:              export IBM_QUANTUM_TOKEN="your-44-char-token"

Run:
    pip install -r requirements.txt
    streamlit run app.py
"""

import os
import random
import hashlib

import streamlit as st
from qiskit import QuantumCircuit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASIS_Z = "Z"   # standard basis   |0>, |1>
BASIS_X = "X"   # hadamard basis   |+>, |->


# ---------------------------------------------------------------------------
# Backend setup (cached so we don't reconnect on every Streamlit rerun)
# ---------------------------------------------------------------------------
@st.cache_resource
def get_backend():
    token = "iRhQ66kROmp7N7YGB6WStLB8vD9wS5g4ViHYJActkBtB"
    if not token:
        from qiskit_aer import AerSimulator
        return AerSimulator(), False

    from qiskit_ibm_runtime import QiskitRuntimeService
    instance = os.environ.get("IBM_QUANTUM_INSTANCE")
    service = QiskitRuntimeService(token=token, instance=instance)
    backend = service.least_busy(operational=True, simulator=False)
    return backend, True


def run_batch(circuits, backend, is_real, shots=1):
    """Submit a batch of 1-qubit circuits as one job, return measured bits."""
    if is_real:
        from qiskit_ibm_runtime import SamplerV2 as RuntimeSampler
        from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager

        pm = generate_preset_pass_manager(backend=backend, optimization_level=1)
        isa_circuits = [pm.run(qc) for qc in circuits]
        sampler = RuntimeSampler(mode=backend)
        job = sampler.run(isa_circuits, shots=shots)
    else:
        from qiskit.primitives import BackendSamplerV2 as LocalSampler
        sampler = LocalSampler(backend=backend)
        job = sampler.run(circuits, shots=shots)

    result = job.result()
    bits = []
    for i in range(len(circuits)):
        counts = result[i].data.c.get_counts()
        bits.append(int(list(counts.keys())[0]))
    return bits


# ---------------------------------------------------------------------------
# BB84 primitives
# ---------------------------------------------------------------------------
def random_bits(n):
    return [random.randint(0, 1) for _ in range(n)]


def random_bases(n):
    return [random.choice([BASIS_Z, BASIS_X]) for _ in range(n)]


def encode_bit(bit: int, basis: str) -> QuantumCircuit:
    qc = QuantumCircuit(1, 1)
    if bit == 1:
        qc.x(0)
    if basis == BASIS_X:
        qc.h(0)
    return qc


def measure_bit(qc: QuantumCircuit, basis: str) -> QuantumCircuit:
    qc = qc.copy()
    if basis == BASIS_X:
        qc.h(0)
    qc.measure(0, 0)
    return qc


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


def run_bb84(n_bits, eavesdropper, message, backend, is_real):
    alice_bits = random_bits(n_bits)
    alice_bases = random_bases(n_bits)
    circuits = [encode_bit(b, ba) for b, ba in zip(alice_bits, alice_bases)]

    eve_bases = None
    if eavesdropper:
        eve_bases = random_bases(n_bits)
        eve_measure_circuits = [measure_bit(qc, eb) for qc, eb in zip(circuits, eve_bases)]
        eve_bits = run_batch(eve_measure_circuits, backend, is_real)
        circuits = [encode_bit(bit, eb) for bit, eb in zip(eve_bits, eve_bases)]

    bob_bases = random_bases(n_bits)
    measured_circuits = [measure_bit(qc, bb) for qc, bb in zip(circuits, bob_bases)]
    bob_bits = run_batch(measured_circuits, backend, is_real)

    sifted_alice, sifted_bob, matched_idx = [], [], []
    for i, (a_bit, a_basis, b_bit, b_basis) in enumerate(
        zip(alice_bits, alice_bases, bob_bits, bob_bases)
    ):
        if a_basis == b_basis:
            sifted_alice.append(a_bit)
            sifted_bob.append(b_bit)
            matched_idx.append(i)

    check_len = max(1, len(sifted_alice) // 4)
    mismatches = sum(a != b for a, b in zip(sifted_alice[:check_len], sifted_bob[:check_len]))
    error_rate = mismatches / check_len if check_len else 0.0

    final_alice_key = sifted_alice[check_len:]
    final_bob_key = sifted_bob[check_len:]

    result = {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "sifted_len": len(sifted_alice),
        "error_rate": error_rate,
        "final_alice_key": final_alice_key,
        "final_bob_key": final_bob_key,
        "keys_match": final_alice_key == final_bob_key,
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
st.set_page_config(page_title="BB84 Quantum Key Distribution", layout="centered")
st.title("BB84 Quantum Key Distribution")
st.caption("Alice and Bob build a shared secret key from qubits, then use it as an AES key.")

backend, is_real = get_backend()
st.sidebar.markdown(f"**Backend:** `{'IBM real hardware — ' + backend.name if is_real else 'Local Aer simulator'}`")

n_bits = st.sidebar.slider("Number of qubits to send", 8, 64, 24, step=4)
eavesdropper = st.sidebar.checkbox("Simulate an eavesdropper (Eve)")
message = st.sidebar.text_input("Message to encrypt", "Meet at the old bridge, 9pm.")
run_clicked = st.sidebar.button("Run BB84", type="primary")

if run_clicked:
    with st.spinner("Sending qubits and measuring..."):
        result = run_bb84(
            n_bits, eavesdropper, message.encode(), backend, is_real
        )

    col1, col2, col3 = st.columns(3)
    col1.metric("Qubits sent", n_bits)
    col2.metric("Sifted (bases matched)", result["sifted_len"])
    col3.metric("QBER (sample)", f"{result['error_rate']:.0%}")

    if result["error_rate"] > 0.11:
        st.error("QBER above threshold — an eavesdropper is likely on the line.")
    else:
        st.success("Line looks clean — no sign of eavesdropping.")

    st.subheader("Final shared key")
    st.write(f"Length: {len(result['final_alice_key'])} bits")
    st.code(
        f"Alice: {''.join(map(str, result['final_alice_key']))}\n"
        f"Bob:   {''.join(map(str, result['final_bob_key']))}",
        language="text",
    )
    if result["keys_match"]:
        st.success("Keys match ✓")
    else:
        st.error("Keys do NOT match — decryption will fail.")

    if result["final_alice_key"]:
        st.code(f"AES key (SHA-256 of raw bits, hex):\n{bits_to_aes_key(result['final_alice_key']).hex()}")

    st.subheader("Message encryption")
    st.write(f"Original: `{message}`")
    if "ciphertext_hex" in result:
        st.code(f"Ciphertext (hex): {result['ciphertext_hex'][:80]}...")
        if result["decrypt_ok"]:
            st.success(f"Bob decrypted: {result['decrypted']!r}")
        else:
            st.error("Bob failed to decrypt — his key didn't match Alice's.")

    with st.expander("Show bit-by-bit basis comparison (first 16)"):
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
    st.info("Set your options in the sidebar and click **Run BB84** to start.")