# Functional Encryption — From IPFE to Turing Machines

> Cybersecurity — Functional Encryption, Part 3  
> Authors: GS · EB · DO | March 2026

---

## Overview

**Functional Encryption (FE)** allows revealing only `f(x)` from an encryption of `x`, without exposing `x` itself. This project traces the natural progression of expressiveness:

```
IPFE                 —>   FE for Circuits   —>   FE for TMs              —>   Registered FE/TM
(linear, fixed dim)      (boolean, fixed n)     (any TM, |x| ∈ ℕ*)         (no authority)
DDH / LWE                LWE (2012)             LWE (2021–22)               LWE (2025)
```

The **shared structural limitation** of IPFE and circuits: the dimension (or input size) must be fixed at scheme construction. Turing Machines break this constraint, since their *description* is constant regardless of input size.

---

## Project Structure

```
Projet-FE/
├── README.md                    # French README
├── code/
│   ├── ipfe_limit.py            # IPFE structural bound (DDH-IPFE, Abdalla et al. PKC 2015)
│   ├── circuit_vs_tm.py         # Boolean circuits vs Turing machines (description size)
│   └── fe_mt_demo.py            # FE for TM simulation: Setup/KeyGen/Enc/Dec
├── proofs/
│   ├── proofs.tex               # Formal proofs document (LaTeX, French)
│   └── proofs.pdf               # Compiled version
├── slides/
│   └── presentation.pptx        # Final presentation slides
└── en/
    ├── README.md                # This file
    └── report_en.md             # Full English report (proofs + code analysis)
```

---

## Code — Overview

All three scripts are **pedagogical** and use only Python ≥ 3.8 standard library. No installation required.

```bash
python3 code/ipfe_limit.py
python3 code/circuit_vs_tm.py
python3 code/fe_mt_demo.py
```

### `ipfe_limit.py` — Structural Bound of IPFE

Simulates the **DDH-IPFE** scheme from Abdalla et al. (PKC 2015) using linear arithmetic over Z_p.

Decryption computes `Σ cᵢyᵢ − r·sk_y mod p`, which cancels the random term `r` exactly and yields `⟨x, y⟩`. Four cases are demonstrated:
- Case 1: correct dimension —> `⟨x, y⟩` recovered (✓)
- Case 2: `enc` with wrong-dimension vector —> `ValueError`
- Case 3: `keygen` with wrong-dimension vector —> `ValueError`
- Case 4: new `Setup` invalidates all previous keys

### `circuit_vs_tm.py` — Boolean Circuits vs Turing Machines

Quantitatively demonstrates the difference between **non-uniform** (circuits) and **uniform** (TM) computation:

| Input size N | `C_count_N` (FE circuits) | `M_count_any` (FE TM) |
|:------------:|:-------------------------:|:---------------------:|
| 4            | Θ(4) gates                | 3 δ-rules (constant)  |
| 100          | Θ(100) gates              | 3 δ-rules (constant)  |
| 10,000       | Θ(10,000) gates           | 3 δ-rules (constant)  |

> **Coherence note**: `C_count_N` computes an **OR** (is any bit 1?), while `M_count_any` counts the integer number of 1-bits. These are intentionally different functions — the key point is description *size* growth, not functional equivalence. Circuit ↔ TM functional coherence is verified in Part 5 using `C_parity_4` and `tm_parity` (same XOR function).

### `fe_mt_demo.py` — FE for TM Simulation

Simulates the four algorithms of the FE for TM scheme from Ananth & Vaikuntanathan (CRYPTO 2021):

- `fe_setup()` — generates `(mpk, msk)` (IBE-GPV from LWE in practice; empty registry here)
- `fe_keygen(registry, M)` — derives `sk_M = H(M)` as IBE cryptographic identity
- `fe_enc(x)` — encrypts `x` via Garbled RAM (simulation: identity, for pedagogical clarity)
- `fe_dec(registry, sk, c)` — executes `M(x)` via step-by-step TM simulation faithful to the formal definition

Three machines instantiated: `M_count` (count 1-bits), `M_parity` (XOR parity), `M_runs` (contiguous blocks). The same functional key is used for inputs ranging from 4 bits to 1000 bits.

---

## Proofs (`proofs/proofs.tex`)

The document covers four results, each preceded by an **Intuition box**:

1. **IPFE Lower Bound** (§3) — proof by contradiction: a hypothetical cross-dimension conversion mechanism would break IND-CPA.
2. **LWE Hardness** (§2.10) — role of noise, Regev reduction (STOC 2005): GapSVP hard —> LWE hard —> post-quantum resistance.
3. **FE for TMs — Selective Security** (§4) — IBE-LWE + Garbled RAM construction, proof by hybrid argument over `q` games.
4. **Adaptive Security via Punctured Programming** (§5) — punctured key `msk[x*]` and blind FHE evaluation.

### Compilation

```bash
cd proofs
pdflatex proofs.tex && pdflatex proofs.tex
```

---

## Code ↔ Proofs Coherence Check

| Code element | Correspondence in `proofs.tex` |
|-------------|-------------------------------|
| `dec()`: `Σ cᵢyᵢ − c₀·sk_y mod p` | Proof Part 2 of Thm 3.1 (linear DDH simulation) |
| `ValueError` on dimension mismatch | Proof Parts 1 & 3 of Thm 3.1 (IND-CPA contradiction) |
| `mt_identity(M) = H(M)` | Construction 4.1, KeyGen: `sk_M ← IBE.KeyGen(msk, H(M))` |
| `fe_enc = identity` | Construction 4.1 Enc: declared simulation (Garbled RAM not implemented) |
| Hybrid argument `H_0 … H_q` | Proof of Thm 4.1, gamebox hybrid games |
| `msk[x*]` (punctured key) | Definition 5.1 + proof of Thm 5.1 |

---

## Key References

| Result | Reference |
|--------|-----------|
| DDH-IPFE | Abdalla, Bourse, De Caro, Pointcheval — PKC 2015 |
| FE for circuits | Gorbunov, Vaikuntanathan, Wee — CRYPTO 2012 |
| LWE & GapSVP reduction | Regev — STOC 2005 / JACM 2009 |
| IBE from LWE (GPV) | Gentry, Peikert, Vaikuntanathan — STOC 2008 |
| Garbled RAM | Lu, Ostrovsky — EUROCRYPT 2013 |
| FE for TMs (selective) | Ananth, Vaikuntanathan — CRYPTO 2021 |
| FE for TMs (adaptive) | Agrawal, Feng, Sarkar, Yadav — ASIACRYPT 2022 |
| Registered FE for TMs | IACR ePrint 2025/967 |
