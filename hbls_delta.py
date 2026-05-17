"""
================================================================================
  HBLS-Δ: Hash-Bound BLS Short Digital Signature Protocol
  CECY 321 — Cryptography Project, University of Jeddah
  Work Done By 1-Zayed ALenazi 2-Osama Hussain 3- Meshari Alharbi.
================================================================================

PURPOSE
-------
This script provides a fully functional simulation of the HBLS-Δ protocol
described in the project report. It implements all five core algorithms:
  1. Key Generation         (Section 4.3.1)
  2. Signing                (Section 4.3.2)
  3. Verification           (Section 4.3.3)
  4. Signature Aggregation  (Section 4.3.4)
  5. Aggregate Verification (Section 4.3.5)

It also runs a complete test suite covering:
  - Normal sign/verify flow (Alice signs, Bob verifies)
  - Multi-signer aggregation (Alice + Bob → single 48-byte aggregate)
  - Tamper detection (modified message → signature rejected)
  - Wrong-key detection (signature from wrong signer → rejected)
  - Cross-context replay protection (same sig in wrong app → rejected)
  - Performance benchmarks (keygen / sign / verify timing)

CRYPTOGRAPHIC LIBRARY
---------------------
We use py_ecc (https://github.com/ethereum/py_ecc), which provides:
  - BLS12-381 elliptic curve groups G1 and G2
  - Scalar multiplication : multiply(point, scalar)
  - Point addition        : add(point1, point2)
  - Bilinear pairing      : pairing(G2_point, G1_point)
  - Public constants      : G1, G2, curve_order r

NOTE ON HASH-TO-CURVE
---------------------
A production implementation uses the IETF hash-to-curve standard
(draft-irtf-cfrg-hash-to-curve-16, Reference [20] in the report). That
standard maps arbitrary bytes to a valid G1 point using a cofactor-clearing
technique. In this educational script we approximate it by hashing the input
to a 256-bit scalar and multiplying the G1 generator — mathematically
equivalent for correctness proofs and demonstrations, though it does not
implement the full Simplified SWU map.

SECURITY NOTE
-------------
This script is for EDUCATIONAL DEMONSTRATION ONLY. It does NOT implement:
  - Constant-time scalar multiplication (timing-safe)
  - Complete addition formulas (SPA-resistant)
  - Projective coordinate randomization (DPA-resistant)
  - Fault-injection double-computation checks
These are required for any production deployment (Sections 10.1-10.5).

INSTALL
-------
  pip install py_ecc

RUN
---
  python3 hbls_delta.py
================================================================================
"""

# =============================================================================
# IMPORTS
# =============================================================================

import hashlib    # SHA-256 for hash_to_scalar and hash_to_G1
import secrets    # Cryptographically secure random number generator (OS-level)
import time       # Performance benchmarking
import sys        # Exit codes for test failures

# Fix 1: Windows encoding fix for special characters (Δ, ✅, etc.)
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Fix 2: py_ecc uses recursive __pow__ which overflows Python's stack.
# We monkey-patch it with an iterative square-and-multiply before importing.
import py_ecc.fields.field_elements as _fe
def _iterative_pow(self, other):
    if other == 0:
        return type(self)([1] + [0] * (len(self.coeffs) - 1)) if hasattr(self, 'coeffs') else type(self)(1)
    if other < 0:
        return _iterative_pow(self, -other).__inv__()
    result = None
    base = self
    exp = int(other)
    while exp > 0:
        if exp & 1:
            result = base if result is None else result * base
        base = base * base
        exp >>= 1
    return result
_fe.FQ.__pow__ = _iterative_pow
_fe.FQP.__pow__ = _iterative_pow

# py_ecc BLS12-381 primitives
# Install: pip install py_ecc
from py_ecc.bls12_381 import (
    G1,           # Generator point of group G1 (compressed: 48 bytes)
    G2,           # Generator point of group G2 (compressed: 96 bytes)
    pairing,      # Bilinear pairing e: G2 x G1 -> GT   (py_ecc: G2 comes first)
    multiply,     # Scalar multiplication: k * P
    add,          # Point addition: P + Q
    curve_order,  # Prime group order r (approx 2^255)
)


# =============================================================================
# SECTION 1 — SYSTEM PARAMETERS
# =============================================================================

# Context identifiers: unique 128-bit tags per application.
# These are the ctx_id values from Section 4.2 of the report.
# In deployment: ctx_id = SHA-256("NCA-KSA-HBLS-Delta-v1" || app_name)[:16]
# Here we use human-readable labels for demonstration clarity.
CTX_ID_EGOV    = b"NCA-KSA-HBLS-Delta-v1-eGovSign-2026"
CTX_ID_BANKING = b"NCA-KSA-HBLS-Delta-v1-BankingSign-2026"

# Target security level (bits)
# curve_order has 255 bits, so Pollard's rho takes ~2^127.5 steps (Section 8.2)
SECURITY_BITS = 128


# =============================================================================
# SECTION 2 — HASH FUNCTIONS
# =============================================================================

def hash_to_scalar(data: bytes) -> int:
    """
    Hash arbitrary bytes to a scalar in [1, r-1] using SHA-256.

    Used for:
      1. Computing the binding tag: t = H_scalar(PK_bytes || ctx_id)
      2. As the inner step of hash_to_G1 (see below)

    The bias from reducing a 256-bit hash modulo r (a 255-bit number) is
    at most 2^{-127}, negligible for 128-bit security.

    Parameters
    ----------
    data : bytes
        Arbitrary-length input.

    Returns
    -------
    int
        A scalar in [1, curve_order - 1].
    """
    digest = hashlib.sha256(data).digest()            # 32 bytes = 256 bits
    scalar = int.from_bytes(digest, byteorder='big') % curve_order
    if scalar == 0:
        scalar = 1    # probability 1/r ≈ 2^{-255}, practically impossible
    return scalar


def hash_to_G1(data: bytes):
    """
    Map arbitrary bytes to a pseudorandom point in G1.

    Production: IETF draft-irtf-cfrg-hash-to-curve-16 (Reference [20]).
    This demo: hash to scalar k, then return k * G1. Cryptographically
    equivalent for proving correctness in the random-oracle model.

    Parameters
    ----------
    data : bytes
        Concatenation of ctx_id || PK_bound_bytes || message.

    Returns
    -------
    G1 point
        A point M in G1 committing to the message and context.
    """
    k = hash_to_scalar(data)    # k in [1, r-1]
    return multiply(G1, k)      # M = k * G1


# =============================================================================
# SECTION 3 — ALGORITHM 1: KEY GENERATION  (Section 4.3.1)
# =============================================================================

def keygen(ctx_id: bytes) -> dict:
    """
    Generate an HBLS-Delta key pair bound to the given application context.

    Steps (Section 4.3.1 of the report):
      1. x  <- random in [1, r-1]           (private key)
      2. PK  = x * Q                         (Q = G2 generator)
      3. t   = H_scalar(encode(PK) || ctx_id)(binding tag)
      4. PK_bound = PK + t*Q = (x+t)*Q      (bound public key)

    The binding tag t ties this public key to the specific application
    ctx_id, preventing rogue-key attacks (Section 6.2).

    Parameters
    ----------
    ctx_id : bytes
        Application context identifier.

    Returns
    -------
    dict with keys:
        'x'        : int   - private key scalar (KEEP SECRET)
        't'        : int   - binding tag scalar (public)
        'PK_bound' : G2 pt - bound public key (published in NCA PKI directory)
        'PK_raw'   : G2 pt - raw public key x*G2 (for display)
        'ctx_id'   : bytes - context this key is bound to
    """
    # Step 1: Generate private key using OS-level entropy (NCS-1 Section 7.1)
    # secrets.randbelow uses /dev/urandom on Linux, BCryptGenRandom on Windows.
    x = secrets.randbelow(curve_order - 1) + 1    # x in [1, r-1]

    # Step 2: Public key base  PK = x * Q
    # Recovering x from PK requires solving ECDLP in G2 (~2^128 operations).
    PK_raw = multiply(G2, x)                       # PK in G2

    # Step 3: Binding tag  t = H_scalar(encode(PK) || ctx_id)
    # t deterministically commits PK to ctx_id.
    # An attacker cannot choose t freely -> rogue-key attack fails (Section 6.2).
    PK_bytes = str(PK_raw).encode('utf-8')
    t = hash_to_scalar(PK_bytes + ctx_id)          # t in [1, r-1]

    # Step 4: Bound public key  PK_bound = PK + t*Q = (x + t)*Q
    t_times_Q = multiply(G2, t)                    # t * Q in G2
    PK_bound  = add(PK_raw, t_times_Q)             # PK_bound in G2

    return {
        'x':        x,          # PRIVATE — never leave the HSM
        't':        t,          # PUBLIC  — published alongside PK_bound
        'PK_bound': PK_bound,   # PUBLIC  — the verifiable identity key
        'PK_raw':   PK_raw,     # for display/audit only
        'ctx_id':   ctx_id,     # context this key is valid in
    }


# =============================================================================
# SECTION 4 — ALGORITHM 2: SIGNING  (Section 4.3.2)
# =============================================================================

def sign(key: dict, message: bytes):
    """
    Sign a message using the HBLS-Delta private key.

    Steps (Section 4.3.2):
      1. M   = H(ctx_id || PK_bound_bytes || message)   (hash to G1 point)
      2. sig = (x + t) * M                               (signature in G1)

    The signature is a single G1 point — 48 bytes compressed.
    This is 25% smaller than ECDSA/EdDSA (64 bytes) at the same security level.

    Parameters
    ----------
    key : dict
        Key dict returned by keygen().
    message : bytes
        The message to sign.

    Returns
    -------
    G1 point
        The signature sig = (x + t) * M.
    """
    x        = key['x']
    t        = key['t']
    PK_bound = key['PK_bound']
    ctx_id   = key['ctx_id']

    # Step 1: Hash message to a G1 curve point.
    # Mixing ctx_id and PK_bound into the hash provides:
    #   (a) Domain separation between applications (Section 6.3)
    #   (b) Binding the signature to this specific signer
    hash_input = ctx_id + str(PK_bound).encode('utf-8') + message
    M = hash_to_G1(hash_input)                     # M in G1

    # Step 2: Compute signature.
    # The effective secret is (x + t) mod r.
    # t is public but is forced by the hash of PK and ctx_id,
    # so knowing t does not help an attacker forge signatures.
    sk_eff = (x + t) % curve_order
    sig    = multiply(M, sk_eff)                   # sig = sk_eff * M in G1

    return sig


# =============================================================================
# SECTION 5 — ALGORITHM 3: VERIFICATION  (Section 4.3.3)
# =============================================================================

def verify(sig, PK_bound, ctx_id: bytes, message: bytes) -> bool:
    """
    Verify an HBLS-Delta signature.

    Steps (Section 4.3.3):
      1. M   = H(ctx_id || PK_bound_bytes || message)
      2. Check e(sig, Q) == e(M, PK_bound)

    Correctness proof (Section 5.5 of the report):
      LHS = e(sig, Q)      = e((x+t)*M, Q) = e(M, Q)^(x+t)
      RHS = e(M, PK_bound) = e(M, (x+t)*Q) = e(M, Q)^(x+t)
      Both sides equal e(M,Q)^(x+t), so they match for any valid signature.

    IMPORTANT — py_ecc argument order:
      pairing(G2_point, G1_point)  [G2 comes FIRST in py_ecc]
      This is the opposite of the mathematical notation e(G1, G2).
      We apply this consistently on both sides, so the equality still holds.

    Parameters
    ----------
    sig      : G1 point - the signature to verify
    PK_bound : G2 point - the signer's bound public key
    ctx_id   : bytes    - application context (must match what was used to sign)
    message  : bytes    - the original message

    Returns
    -------
    bool
        True if valid, False otherwise.
    """
    # Step 1: Recompute message hash (same inputs as in sign())
    hash_input = ctx_id + str(PK_bound).encode('utf-8') + message
    M = hash_to_G1(hash_input)                     # M in G1

    # Step 2: Pairing equality check
    # LHS: e(sig, G2)          — sig is in G1, G2 is the generator
    # RHS: e(M,   PK_bound)    — M is in G1, PK_bound is in G2
    # py_ecc signature: pairing(arg_in_G2, arg_in_G1)
    lhs = pairing(G2, sig)          # e(sig, G2)
    rhs = pairing(PK_bound, M)      # e(M, PK_bound)

    return lhs == rhs


# =============================================================================
# SECTION 6 — ALGORITHMS 4 & 5: AGGREGATION  (Sections 4.3.4, 4.3.5)
# =============================================================================

def aggregate_signatures(signatures: list):
    """
    Combine n individual signatures into one aggregate signature.

    Aggregation = point addition in G1 (Section 4.3.4):
      sig_agg = sig_1 + sig_2 + ... + sig_n

    The result is still a single G1 point — 48 bytes, regardless of n.
    This is one of BLS's key advantages over ECDSA and EdDSA.

    Parameters
    ----------
    signatures : list of G1 points

    Returns
    -------
    G1 point
        The aggregate signature.
    """
    agg = signatures[0]
    for sig in signatures[1:]:
        agg = add(agg, sig)          # elliptic curve point addition in G1
    return agg


def verify_aggregate(agg_sig, signers: list, messages: list,
                     ctx_id: bytes) -> bool:
    """
    Verify an aggregate HBLS-Delta signature.

    Equation (Section 4.3.5):
      e(sig_agg, Q) == e(M_1, PK_1) * e(M_2, PK_2) * ... * e(M_n, PK_n)

    '*' here is multiplication in the target group GT = Fp12.
    Each M_i includes PK_bound_i in its hash, so an attacker cannot insert
    a rogue public key to cancel out another signer (rogue-key resistance).

    Parameters
    ----------
    agg_sig  : G1 point        - the aggregate signature
    signers  : list of G2 pts  - each signer's PK_bound
    messages : list of bytes   - message each signer signed
    ctx_id   : bytes           - common application context

    Returns
    -------
    bool
        True if the aggregate is valid for all (message, PK_bound) pairs.
    """
    # LHS: e(sig_agg, G2)
    lhs = pairing(G2, agg_sig)

    # RHS: product of individual pairings in GT (Fp12 multiplication)
    M0  = hash_to_G1(ctx_id + str(signers[0]).encode() + messages[0])
    rhs = pairing(signers[0], M0)               # first term in GT

    for pk_i, msg_i in zip(signers[1:], messages[1:]):
        M_i   = hash_to_G1(ctx_id + str(pk_i).encode() + msg_i)
        rhs_i = pairing(pk_i, M_i)
        rhs   = rhs * rhs_i                     # Fp12 multiplication (GT group op)

    return lhs == rhs


# =============================================================================
# SECTION 7 — HELPER: PRETTY PRINTING
# =============================================================================

def short_hex(point, label: str = "") -> str:
    """Format a curve point showing only the first 16 hex chars of x-coord."""
    x = point[0]
    # G2 x-coordinate is FQ2 (has .coeffs); G1 x-coordinate is FQ (has .n)
    if hasattr(x, 'coeffs'):
        raw = int(x.coeffs[0].n)   # take real part of FQ2
    elif hasattr(x, 'n'):
        raw = int(x.n)             # FQ element
    else:
        raw = int(x)
    return f"{label}: 0x{hex(raw)[2:18]}...  (48-byte G1 / 96-byte G2 point)"


def sep(title: str = ""):
    w = 72
    if title:
        p = (w - len(title) - 2) // 2
        print("\n" + "─" * p + f" {title} " + "─" * (w - p - len(title) - 2))
    else:
        print("\n" + "─" * w)


# =============================================================================
# SECTION 8 — TEST SUITE
# =============================================================================

def run_tests() -> bool:
    """
    Execute all HBLS-Delta protocol tests and print a structured report.

    Tests T-01 through T-07 map directly to sections of the report
    and should each be screenshot for submission.
    """
    all_passed = True

    # ─── BANNER ───────────────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("  HBLS-Δ  —  Hash-Bound BLS Short Digital Signature Protocol")
    print("  CECY 321 Cryptography  |  University of Jeddah")
    print("  Implementation and Validation Test Suite")
    print("=" * 72)
    print(f"  Curve          : BLS12-381")
    print(f"  Group order r  : {curve_order.bit_length()}-bit prime  (approx 2^255)")
    print(f"  Security level : {SECURITY_BITS}-bit classical security")
    print(f"  Sig size       : 48 bytes  (one compressed G1 point)")
    print(f"  Public key size: 96 bytes  (one compressed G2 point)")
    print(f"  Library        : py_ecc  (Ethereum Foundation)")
    print("=" * 72)

    # ─── SETUP: Key generation for Alice and Bob ──────────────────────────────
    sep("SETUP — Key Generation for Alice and Bob")
    print(f"\n  Context ID (eGov application): {CTX_ID_EGOV.decode()}\n")

    alice = keygen(CTX_ID_EGOV)
    bob   = keygen(CTX_ID_EGOV)

    print(f"  Alice secret key x  : 0x{alice['x']:016x}...  (SECRET — stays in HSM)")
    print(f"  Alice binding tag t : 0x{alice['t']:016x}...  (public)")
    print(f"  {short_hex(alice['PK_bound'], 'Alice PK_bound (G2 point)')}")
    print()
    print(f"  Bob   secret key x  : 0x{bob['x']:016x}...  (SECRET)")
    print(f"  Bob   binding tag t : 0x{bob['t']:016x}...  (public)")
    print(f"  {short_hex(bob['PK_bound'], 'Bob   PK_bound (G2 point)')}")

    # ─── T-01: Normal sign and verify ────────────────────────────────────────
    sep("T-01 | Normal Sign and Verify  (Alice signs, Bob verifies)")

    alice_msg = b"Approve payment transfer: 5,000 SAR | Ref: TXN-2026-00471"
    print(f"\n  Message : \"{alice_msg.decode()}\"")

    alice_sig = sign(alice, alice_msg)
    print(f"  {short_hex(alice_sig, 'Signature  (G1 point)')}")
    print(f"  Signature size: 48 bytes  (25% smaller than ECDSA at same security)")

    r01 = verify(alice_sig, alice['PK_bound'], CTX_ID_EGOV, alice_msg)
    ok01 = r01
    all_passed &= ok01
    icon = "PASS" if ok01 else "FAIL"
    print(f"\n  e(sig, G2) == e(M, PK_bound) : {r01}")
    print(f"  >>> T-01 : {icon} ({'✅' if ok01 else '❌'})")

    # ─── T-02: Bob signs a different message ─────────────────────────────────
    sep("T-02 | Second Signer  (Bob signs a different message)")

    bob_msg = b"Grant system access: role=administrator | Session: SES-20260512"
    print(f"\n  Message : \"{bob_msg.decode()}\"")

    bob_sig = sign(bob, bob_msg)
    print(f"  {short_hex(bob_sig, 'Bob signature (G1 point)')}")

    r02 = verify(bob_sig, bob['PK_bound'], CTX_ID_EGOV, bob_msg)
    ok02 = r02
    all_passed &= ok02
    icon = "PASS" if ok02 else "FAIL"
    print(f"\n  Verification result: {r02}")
    print(f"  >>> T-02 : {icon} ({'✅' if ok02 else '❌'})")

    # ─── T-03: Tamper detection ───────────────────────────────────────────────
    sep("T-03 | Tamper Detection  (Integrity — Section 2.7.1)")

    tampered = b"Approve payment transfer: 9,999 SAR | Ref: TXN-2026-00471"
    print(f"\n  Original  : \"{alice_msg.decode()}\"")
    print(f"  Tampered  : \"{tampered.decode()}\"")
    print(f"  Change    : 5,000 SAR  ->  9,999 SAR")

    r03 = verify(alice_sig, alice['PK_bound'], CTX_ID_EGOV, tampered)
    ok03 = (r03 == False)    # MUST reject tampered message
    all_passed &= ok03
    icon = "PASS" if ok03 else "FAIL"
    print(f"\n  Verification on tampered message : {r03}   (expected: False)")
    print(f"  Tamper correctly detected         : {ok03}")
    print(f"  >>> T-03 : {icon} ({'✅' if ok03 else '❌'})")

    # ─── T-04: Wrong-key detection ────────────────────────────────────────────
    sep("T-04 | Wrong-Key Detection  (Authentication — Section 2.7.1)")

    print(f"\n  Alice's signature applied to Alice's message.")
    print(f"  Verifying with BOB's public key instead of Alice's...")

    r04 = verify(alice_sig, bob['PK_bound'], CTX_ID_EGOV, alice_msg)
    ok04 = (r04 == False)    # MUST reject: wrong public key
    all_passed &= ok04
    icon = "PASS" if ok04 else "FAIL"
    print(f"\n  Verification with wrong PK : {r04}   (expected: False)")
    print(f"  Wrong-key correctly rejected: {ok04}")
    print(f"  >>> T-04 : {icon} ({'✅' if ok04 else '❌'})")

    # ─── T-05: Cross-context replay protection ────────────────────────────────
    sep("T-05 | Cross-Context Replay Protection  (Section 6.3)")

    print(f"\n  Alice signed in context : {CTX_ID_EGOV.decode()}")
    print(f"  Attacker replays sig in : {CTX_ID_BANKING.decode()}")
    print(f"  Same (message, sig, PK_bound) — only ctx_id changes.")

    r05 = verify(alice_sig, alice['PK_bound'], CTX_ID_BANKING, alice_msg)
    ok05 = (r05 == False)    # MUST reject: ctx_id mismatch changes M
    all_passed &= ok05
    icon = "PASS" if ok05 else "FAIL"
    print(f"\n  Verification with wrong ctx_id  : {r05}   (expected: False)")
    print(f"  Replay attack correctly blocked  : {ok05}")
    print(f"  >>> T-05 : {icon} ({'✅' if ok05 else '❌'})")

    # ─── T-06: Signature aggregation ─────────────────────────────────────────
    sep("T-06 | Signature Aggregation  (Sections 4.3.4 + 4.3.5)")

    print(f"\n  Aggregating Alice's sig  +  Bob's sig  ->  one 48-byte sig")
    print(f"  Alice message : \"{alice_msg.decode()}\"")
    print(f"  Bob   message : \"{bob_msg.decode()}\"")

    agg_sig = aggregate_signatures([alice_sig, bob_sig])
    print(f"\n  {short_hex(agg_sig, 'Aggregate sig (G1 point)')}")
    print(f"  Aggregate size: 48 bytes  (same size as a single signature!)")

    signers  = [alice['PK_bound'], bob['PK_bound']]
    messages = [alice_msg, bob_msg]
    r06 = verify_aggregate(agg_sig, signers, messages, CTX_ID_EGOV)
    ok06 = r06
    all_passed &= ok06
    icon = "PASS" if ok06 else "FAIL"
    print(f"\n  e(sig_agg,G2) == e(M1,PK1)*e(M2,PK2) : {r06}")
    print(f"  >>> T-06 : {icon} ({'✅' if ok06 else '❌'})")

    # ─── T-07: Performance benchmarks ────────────────────────────────────────
    sep("T-07 | Performance Benchmarks  (Section 12.1)")

    REPS = 3
    bench_msg = b"Benchmark message for HBLS-Delta performance measurement"
    print(f"\n  Running {REPS} repetitions per operation ...\n")

    # Keygen
    t0 = time.perf_counter()
    for _ in range(REPS):
        keygen(CTX_ID_EGOV)
    keygen_ms = (time.perf_counter() - t0) / REPS * 1000

    # Sign
    t0 = time.perf_counter()
    for _ in range(REPS):
        sign(alice, bench_msg)
    sign_ms = (time.perf_counter() - t0) / REPS * 1000

    # Verify
    bench_sig = sign(alice, bench_msg)
    t0 = time.perf_counter()
    for _ in range(REPS):
        verify(bench_sig, alice['PK_bound'], CTX_ID_EGOV, bench_msg)
    verify_ms = (time.perf_counter() - t0) / REPS * 1000

    print(f"  {'Operation':<28} {'This script':>14}  {'blst C lib (Table 12.1)':>24}")
    print(f"  {'─' * 68}")
    print(f"  {'Key Generation':<28} {keygen_ms:>11.0f} ms  {'~0.6 ms':>24}")
    print(f"  {'Sign':<28} {sign_ms:>11.0f} ms  {'~0.9 ms':>24}")
    print(f"  {'Verify':<28} {verify_ms:>11.0f} ms  {'~2.1 ms':>24}")
    print()
    print("  py_ecc is a pure-Python reference library used here for clarity.")
    print("  The blst column shows the optimised C library cited in the report.")
    print("  Mathematical correctness is identical; only execution speed differs.")
    print(f"  >>> T-07 : PASS ✅  (benchmarks completed)")

    # ─── SUMMARY ──────────────────────────────────────────────────────────────
    sep("TEST SUMMARY")
    results = [
        ("T-01", "Normal sign and verify (Alice -> Bob)",           ok01),
        ("T-02", "Second signer (Bob signs different message)",      ok02),
        ("T-03", "Tamper detection — integrity enforced",            ok03),
        ("T-04", "Wrong-key detection — authentication enforced",    ok04),
        ("T-05", "Cross-context replay protection",                  ok05),
        ("T-06", "Signature aggregation: 2 signers -> 1 sig",        ok06),
        ("T-07", "Performance benchmarks",                           True),
    ]
    print()
    for code, name, passed in results:
        icon = "✅  PASS" if passed else "❌  FAIL"
        print(f"  {code}  {icon}   {name}")

    print()
    if all_passed:
        print("  " + "=" * 68)
        print("  ALL TESTS PASSED — HBLS-Δ protocol implementation verified ✅")
        print("  " + "=" * 68)
    else:
        print("  " + "=" * 68)
        print("  SOME TESTS FAILED — review output above for details ❌")
        print("  " + "=" * 68)
    print()
    return all_passed


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
