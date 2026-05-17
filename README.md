# HBLS-Δ: Hash-Bound BLS Short Digital Signature Protocol

This repository contains a reference Python implementation of the **HBLS-Δ** protocol, a short digital signature scheme built on the BLS12-381 elliptic curve. 

Traditional signatures like ECDSA are 64 bytes. HBLS-Δ compresses signatures to just 48 bytes while maintaining 128-bit classical security, making it highly efficient for bandwidth-constrained environments.

## Key Features
* **Built-in Rogue-Key Protection:** Uses deterministic key-binding to secure signature aggregation.
* **Cross-Context Replay Protection:** Application-specific domain tagging stops signatures from being replayed across different systems.
* **NCA Compliance Mapping:** Designed to align with Saudi Arabia's Essential Cybersecurity Controls (ECC-2:2024) and National Cryptographic Standards (NCS-1:2020).

## Dependencies
This implementation relies on the Ethereum Foundation's `py_ecc` library for pairing-based cryptography over BLS12-381.

```bash
pip install py_ecc
