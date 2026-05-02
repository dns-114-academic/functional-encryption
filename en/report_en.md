# Functional Encryption — From Inner Products to Turing Machines
## Definitions, Constructions, and Proofs — Full English Report

**Cybersecurity — Functional Encryption, Part 3 | March 2026**  
Authors: GS · EB · DO

---

## Abstract

This document presents the definitions and proofs underlying the presentation *From IPFE to Turing Machines*. Four results are developed: (1) the algebraic lower bound of IPFE, (2) the hardness of LWE and its worst-case reduction to GapSVP (Regev 2005), (3) the FE for TM construction from LWE (Ananth-Vaikuntanathan, CRYPTO 2021) with a selective IND-CPA proof via hybrid argument, and (4) adaptive security via Punctured Programming (Agrawal et al., ASIACRYPT 2022). Each proof is preceded by an **intuition box** explaining the informal idea before the formal demonstration. The Python simulations (`ipfe_limit.py`, `fe_mt_demo.py`, `circuit_vs_tm.py`) adopt a procedural style; sources for each construction are detailed in the script headers.

---

## 1. Introduction

### Context

Functional Encryption (FE) generalizes public-key encryption by allowing fine-grained control over disclosed information. Rather than revealing the entire message `x`, a functional key `sk_f` reveals only `f(x)`.

IPFE (Inner-Product FE) realizes this paradigm for linear functions `f_y(x) = ⟨x, y⟩`, with a fundamental limitation: the dimension `n` is fixed at Setup. Turing Machines break this limitation: an FE scheme for TMs satisfies `Dec(sk_M, Enc(x)) = M(x)` for any `x ∈ {0,1}*`, with a single key `sk_M` valid for any input size.

### Organization

- **Section 2**: Definitions (PKE, FE, IPFE, Circuit, TM, Garbled RAM, LWE and its hardness).
- **Section 3**: IPFE lower bound.
- **Section 4**: FE for TMs — construction and security proof.
- **Section 5**: Adaptive security via Punctured Programming.
- **Section 6**: State of the art and open problems.

---

## 2. Definitions

### 2.1 Public-Key Encryption

A PKE scheme is a tuple (Setup, KeyGen, Enc, Dec) satisfying completeness: `Pr[Dec(sk, Enc(pk, m)) = m] = 1`. Its limitation: Dec reveals `m` entirely or nothing — no granularity over disclosed information.

### 2.2 Functional Encryption (Boneh-Sahai-Waters 2011)

Let F = {f : X → Y} be a function family. An FE scheme for F is a tuple (Setup, KeyGen, Enc, Dec):
- `Setup(1^λ) → (mpk, msk)`
- `KeyGen(msk, f) → sk_f`, for `f ∈ F`
- `Enc(mpk, x) → c`, for `x ∈ X`
- `Dec(sk_f, c) → f(x)`

**Fundamental property**: possessing `sk_f` reveals *only* `f(x)`; no other information about `x` is accessible.

### 2.3 IND-CPA Security

The IND-CPA game between challenger C and adversary A:
1. C computes `(mpk, msk) ← Setup(1^λ)`, sends `mpk` to A.
2. A requests keys `sk_{f_1}, …, sk_{f_q}` via `KeyGen(msk, ·)`.
3. A submits `x_0, x_1 ∈ X` such that `f_i(x_0) = f_i(x_1)` for all `i`.
4. C draws `b ← {0,1}`, returns `c* = Enc(mpk, x_b)`.
5. A may continue queries (same constraint).
6. A outputs `b' ∈ {0,1}`.

The advantage is `|Pr[b'=b] - 1/2|`. The scheme is IND-CPA secure iff for every PPT A, this advantage is negligible in λ.

The constraint `f_i(x_0) = f_i(x_1)` is necessary: what the keys already reveal must not allow distinguishing. Without it, the definition is trivially unsatisfiable (take `f = id`).

**Selective vs. Adaptive security:**
- *Selective*: A announces `x_0, x_1` *before* seeing `mpk`. The reducer can program `mpk` accordingly — simpler model.
- *Adaptive*: A chooses `x_0, x_1` *after* seeing `mpk` and obtaining keys — realistic attack model.
Adaptive security strictly implies selective security.

### 2.4 IPFE

IPFE is an FE scheme for:
`F^(n)_IP = {f_y : x ↦ ⟨x, y⟩ mod p | y ∈ Z_p^n}`
where `n ∈ N` is the **dimension fixed at Setup** and `p` is prime.

### 2.5 Boolean Circuit

A boolean circuit is a DAG whose leaves are inputs (bits), internal nodes are gates (AND, OR, NOT, XOR), and roots are outputs. The size `|C|` and depth `d(C)` are **fixed at construction**.

### 2.6 Turing Machine

A deterministic TM is `M = (Q, Σ, Γ, δ, q_0, q_acc, q_rej)` with `δ : Q × Γ → Q × Γ × {L, R}`. The description `|M|` is a **constant independent of `|x|`**; the same `M` handles inputs of any size; running time `T_M(n)` varies with `n`.

An FE scheme for TMs satisfies: `|c| = poly(λ, |x|)`, `|sk_M| = poly(λ, |M|)`.

### 2.7 Garbled RAM (Lu-Ostrovsky 2013)

A Garbled RAM (Garble, Eval) satisfies:
- `Garble(M, x) → (M̃, x̃)` (scrambles the execution)
- `Eval(M̃, x̃) → M(x)` (returns only the result)

**Simulation security**: there exists a simulator S such that `(M̃, x̃) ≈_c S(M(x), T_M(|x|), |M|, |x|)`. The evaluator learns nothing about M or x, only M(x) and sizes.

*Remark*: A Yao Garbled Circuit would require copying the circuit for each TM step, giving size `T_M(n) · poly(λ)` — too large. The Garbled RAM directly evaluates a RAM (equivalent to the TM) and uses ORAM to mask the memory access pattern; the ORAM overhead is only polylogarithmic in memory size.

### 2.8 LWE Assumption (Regev 2005)

Decision-LWE_{n,m,q,χ}: distinguish `(A, As + e) ≈_c (A, u)` for `A ← Z_q^{m×n}`, `s ← Z_q^n`, `e ← χ` (discrete Gaussian noise), `u ← Z_q^m`.

### 2.9 Why LWE is Hard

**Intuition — The role of noise.** The attacker observes `A` (public random matrix) and `b = As + e mod q`, but sees neither `s` nor `e`. Without noise, solving `b = As mod q` is trivial by Gaussian elimination. The noise `e` makes all classical algebraic operations useless: they propagate and amplify the error until the result is unexploitable. The hardness then comes from a deep connection with the geometry of Euclidean lattices.

**Level 1: why noise makes direct inversion impossible.** Without noise, `b = As mod q` is a linear system over Z_q solvable in O(n³). With noise `e` whose entries are small relative to `q`, one must control the ratio `‖e‖/q`. The choice of distribution χ (discrete Gaussian of parameter αq, with `α = o(1/√n log n)`) calibrates this tradeoff. Any linear manipulation of `b` to isolate `s` causes `e` to grow until it becomes indistinguishable from a random vector in Z_q^m.

**Level 2: connection to Euclidean lattices and GapSVP.** The LWE instance `(A, b = As + e)` implicitly defines a Euclidean lattice `Λ(A) = {A^T z mod q | z ∈ Z^m}`. Geometrically, `s` is a point of `Λ(A)` slightly perturbed by `e`: recovering `s` from `b` means finding the *closest* lattice point to `b`. This is exactly the Bounded Distance Decoding (BDD) problem, itself an instance of the Shortest Vector Problem: BDD ⊆ SVP.

**Theorem (Regev, STOC 2005):** For any `α ∈ (0,1)` with `αq ≥ 2√n`, there exists a polynomial-time quantum reduction: solving LWE_{n,q,α} ⟹ solving GapSVP_γ in the worst case, with `γ = O(√n / α)`.

By contrapositive: GapSVP hard ⟹ LWE hard. LWE security thus rests on worst-case hardness of GapSVP, not merely average-case. GapSVP_γ with `γ = poly(n)` is NP-hard under `P ≠ NP`, and **no subexponential quantum algorithm** (Shor, etc.) is known for SVP or GapSVP, grounding LWE's post-quantum resistance.

---

## 3. IPFE Lower Bound

**Intuition.** The inner product `⟨x, y⟩ = Σ xᵢyᵢ` is only defined between vectors of the same size. If one tries to encrypt a vector of dimension `n' ≠ n` with a scheme designed for dimension `n`, an irreducible ambiguity arises: if `n' > n`, the extra components `x_{n+1}, …, x_{n'}` have no partner index in `y ∈ Z_p^n`; if `n' < n`, the last components of `y` have no partner in `x'`. This is not an implementation choice to be worked around — it is an *algebraic* constraint. The formal proof shows that a hypothetical conversion mechanism would allow an adversary to recover a component of `x` in plaintext, breaking IND-CPA.

**Theorem 3.1 (IPFE Dimensional Constraint):** Let Π be an IPFE scheme for `F^(n)_IP`. For any `x' ∈ Z_p^{n'}` with `n' ≠ n`, it is impossible to compute `⟨x', y⟩` with the keys of Π. A complete new Setup (invalidating all keys) is required.

**Proof sketch (three parts):**

*Part 1 — Algebraic constraint of the inner product.* For `n' > n`: the vector `x'` has `n' - n` extra components `x_{n+1}, …, x_{n'}`. No key `sk_y` generated for `y ∈ Z_p^n` "sees" these coordinates. For `n' < n`: the vector `y ∈ Z_p^n` has `n - n'` components with no partner in `x' ∈ Z_p^{n'}`.

*Part 2 — The master key encodes the dimension.* In Abdalla et al. (DDH), `msk = s ∈ Z_p^n`. Encryption produces `Enc(mpk, x) = (g^r, g^{x_1+rs_1}, …, g^{x_n+rs_n}) ∈ G^{n+1}` — a tuple whose structure reveals and enforces dimension `n`. In the simulation (`ipfe_limit.py`): `Enc` returns `(r, [c_1, …, c_n])` where `c_i = x_i + r·sᵢ mod p`. Dec computes `Σ cᵢyᵢ - r·sk_y mod p`, which correctly yields `Σ xᵢyᵢ` since `r` cancels algebraically. An `enc(s, [12,15,9,7,3])` call raises a `ValueError` not because of a programming defect, but because the scheme can only form an `(n+1)`-tuple structured around the `n` components of `msk`.

*Part 3 — Key invalidation (by contradiction).* Suppose there exists a conversion mechanism φ such that `φ(Enc(mpk, x'))` is decryptable by dimension-`n` keys. Let `x' = (x_0, z)` with `x_0 ∈ Z_p^n` and `z ∈ Z_p` a secret value. The adversary requests key `sk_{e_{n+1}}`. By hypothesis, Dec(sk_{e_{n+1}}, φ(Enc(mpk, x'))) = z, recovering `z` in plaintext from the encryption of `(x_0, z)`, directly violating IND-CPA. Therefore φ cannot exist; the only option is to run `Setup(1^λ, n')` with the new dimension, producing an independent `msk'` and invalidating all prior scheme keys.

**Corollary:** IPFE cannot express, in a single instance, any program P accepting variable-size inputs (e.g., sorting, counting, parsing on streams of arbitrary length).

**Remark — Circuits and the same limitation.** A circuit C of size T and n inputs can only evaluate n-bit inputs. For inputs of size up to N, a worst-case circuit of size O(N·cost(f)) is needed, growing linearly with N. The fundamental difference is between non-uniform computation (circuits: different description for each size n) and uniform computation (TMs: same description M for all n). This uniformity is what allows `|sk_M| = poly(λ, |M|)` independently of `|x|` in FE for TMs.

---

## 4. FE for TMs from LWE

### 4.1 Main Theorem

**Theorem 4.1 (Ananth-Vaikuntanathan, CRYPTO 2021):** Under the LWE assumption and bounded collusion `q = poly(λ)`, there exists an FE scheme for TMs satisfying selective IND-CPA security, with:
- `|c| = poly(λ, |x|)`
- `|sk_M| = poly(λ, |M|)`
- `T_Dec = poly(λ, T_M(|x|))`

### 4.2 Construction (IBE-LWE + Garbled RAM)

Using IBE from LWE (GPV 2008) and Garbled RAM (Lu-Ostrovsky 2013):

**Setup(1^λ):** Run `(mpk_IBE, msk_IBE) ← IBE.Setup(1^λ)`. Set `(mpk, msk) = (mpk_IBE, msk_IBE)`.

**KeyGen(msk, M):** Generate an IBE key for identity `id(M) = H(M)` (hash of M's description):
`sk_M ← IBE.KeyGen(msk_IBE, id(M))`
*Why use H(M) as identity?* IBE binds each key to a public identity. By taking H(M), we ensure `sk_M` is derived specifically for M: decryption will only work if the IBE key presented corresponds to the TM M that produced this ciphertext. Size: `|sk_M| = poly(λ, |M|)`, independent of `|x|`.

**Enc(mpk, x):** Choose `r ← {0,1}^λ` and compute:
`(M̃_univ, x̃) ← Garble(M_univ, x; r)`
The ciphertext is `c = (M̃_univ, IBE.Enc(mpk_IBE, K_r))` where `K_r` is the Garbled RAM unblinding key tied to `r`. Size: `|c| = poly(λ, |x|)`.

**Dec(sk_M, c):**
1. Decrypt IBE to obtain `K_r` via `sk_M`.
2. Compute `Eval(M̃_univ, x̃) → M(x)`.

*Why this works:* `sk_M` is the IBE key for `id(M)`, and the ciphertext contains `IBE.Enc(mpk, K_r)` tied to this identity. The Garbled RAM then gives M(x) without revealing x directly.

**Simulation (`fe_mt_demo.py`):** `fe_setup()` returns an empty registry; `fe_keygen(registry, M)` sets `sk = mt_identity(M) = SHA256(M.delta)[:16]`; `fe_enc(x) = x` (identity for clarity); `fe_dec` runs `mt_run(M, x)`.

### 4.3 Security Proof (Selective)

**Intuition — General strategy.** The selective adversary knows `x_0, x_1` before seeing `mpk`, and obtains `q` keys `sk_{M_1}, …, sk_{M_q}` with `M_i(x_0) = M_i(x_1)`. The idea is to replace the keys one by one with *simulated keys*: keys that produce the correct results `M_i(x_0) = M_i(x_1)` without needing to see `x_b` in plaintext. At each step one key changes, and the game does not change (computationally) for the adversary. At the last game (H_q), all keys are simulated and the ciphertext is `Enc(x_0)` — the adversary can no longer guess `b`. This is the **hybrid argument**: if the adversary has a noticeable advantage between H_0 and H_q, there exists an index k where H_{k-1} and H_k are distinguishable, contradicting Garbled RAM security.

**Hybrid chain:**
- H_0: real game. `c* = Enc(mpk, x_b)`, `b ← {0,1}`. All keys generated normally.
- H_k (1 ≤ k ≤ q): the first k keys are simulated. The simulator S_k generates `sk_{M_1}^sim, …, sk_{M_k}^sim` that produce `M_i(x_0)` without knowing `x_b`. The ciphertext becomes `c* = Enc(mpk, x_0)` (independent of b). Remaining keys normal.

**Transition H_{k-1} → H_k.** We replace `sk_{M_k}` (normal) with `sk_{M_k}^sim` (simulated). Since `M_k(x_0) = M_k(x_1)`, the Garbled RAM produces the same output on `x_0` and `x_1` for `M_k`. A simulator can therefore generate `sk_{M_k}^sim` that correctly evaluates to `M_k(x_0)` without knowing `x_0` in plaintext. If A distinguishes H_{k-1} from H_k with advantage ε, we build a reducer B_k that distinguishes the real Garbled RAM from its simulation with the same advantage.

**Final game H_q.** In H_q, all keys are simulated and `c* = Enc(mpk, x_0)`, independent of b. IBE IND-CPA security guarantees mpk does not reveal x_0, so `Pr[A wins in H_q] = 1/2`.

**Telescoping bound:**
`Adv^FE_A(λ) ≤ Σ_{k=1}^q Adv^GRAM_{B_k}(λ) + Adv^IBE_{B_IBE}(λ) ≤ (q+1)·negl(λ) = negl(λ)`

---

## 5. Adaptive Security via Punctured Programming

**Intuition — Why the selective proof is insufficient.** In the selective proof, the reducer knows `x_0, x_1` before building `mpk` and can "program" it accordingly. In adaptive mode, `x_0, x_1` are chosen *after* A has seen `mpk` — the reducer cannot anticipate.

**Solution — Punctured key `msk[x*]`.** We create a "punctured" version of `msk` that works normally for all inputs except `x*`, and at `x*` does not reveal `f(x*)`. If `f(x*) = f(x')` for a known `x'`, the punctured key can still generate a correct `sk_f` (the value `f(x*)` does not discriminate). FHE allows evaluating `M_k` "blindly": from `Enc_FHE(x_0)`, compute `Enc_FHE(M_k(x_0))` without seeing `x_0` in plaintext.

**Theorem 5.1 (Agrawal-Feng-Sarkar-Yadav, ASIACRYPT 2022):** Under LWE + IBE + FHE (without iO), for bounded collusion `q`, there exists an FE scheme for TMs satisfying adaptive IND-CPA security.

**Adaptive hybrid argument:**
- H_0: adaptive real game. `c* = Enc(mpk, x_b)`, `b ← {0,1}`. All keys normal.
- H_k: keys `sk_{M_1}, …, sk_{M_k}` come from punctured key `msk[x_0]`. The ciphertext is `Enc(mpk, x_0)` (independent of b). Remaining keys normal.

**Transition H_{k-1} → H_k.** Replace `sk_{M_k}` with the version from `msk[x_0]`. Since `M_k(x_0) = M_k(x_1)`, the punctured key can generate the correct `sk_{M_k}` for any `x ≠ x_0`. *Role of FHE:* the reducer computes `Enc_FHE(M_k(x_0))` from `Enc_FHE(x_0)` without seeing `x_0` (homomorphic evaluation of `M_k` on the FHE ciphertext of `x_0`). Indistinguishability `H_{k-1} ≈_c H_k` reduces to FHE security.

**Final bound:** `Adv^FE_A(λ) ≤ Σ_{k=1}^q Adv^FHE_{B_k}(λ) + Adv^IBE_{B_IBE}(λ) ≤ (q+1)·negl(λ) = negl(λ)`

*Why not iO?* For general circuits, the selective → adaptive transition requires indistinguishability obfuscation (iO). Agrawal et al. avoid it by exploiting the *uniform* structure of TMs: the same program with variable time allows a more efficient Punctured Programming than with circuits.

---

## 6. State of the Art

| Result | Year | Functions | Security | Assumptions | Collusion |
|--------|------|-----------|----------|-------------|-----------|
| Abdalla-CF | 2015 | ⟨·, ·⟩ | Adaptive | DDH | Unbounded |
| Gorbunov-VW | 2012 | Circuits | Selective | LWE | Bounded |
| Ananth-V | 2021 | TMs | Selective | LWE | Bounded |
| Agrawal et al. | 2022 | TMs | **Adaptive** | LWE+IBE+FHE | Bounded |
| Registered | 2025 | TMs | Adaptive | LWE | No authority |

**Registered FE for TMs (2025):** Classical FE requires a central Key Authority — a single point of trust. In Registered FE, each user `i` generates `(pk_i, sk_i)`, registers `pk_i` with an untrusted public helper, and obtains functional keys without exposing `sk_i`. No central authority.

**Open problems:**
- **Succinct FE**: building FE for TMs with `|c| = poly(λ)` independent of `T_M(|x|)` from standard assumptions (without iO) remains open.
- **Efficiency**: current LWE parameters (`n ≈ 1024–4096`, `q ≈ 2^100`) make these schemes non-deployable. Reduction via module-LWE and algebraic lattices is an active direction.
- **Unbounded collusion**: security for arbitrary collusion requires iO. Realizing iO from standard assumptions (Jain-Lin-Sahai 2021: LWE+LPN+DDH) is known but practicality remains open.

---

## Code Verification Report

### `ipfe_limit.py` — (✓) Correct

All four demonstration cases execute as expected:
- **Case 1**: ⟨[12,15,9,7], [1,1,1,0]⟩ = 36 recovered exactly. The algebraic cancellation of `r` is verified.
- **Case 2**: `ValueError` on 5-element vector with 4-element scheme.
- **Case 3**: `ValueError` on KeyGen with wrong-dimension key vector.
- **Case 4**: Re-setup with n=5 produces correct results; old key gives incoherent output (demonstrates invalidation).

The Dec formula `Σ cᵢyᵢ - c₀·sk_y mod p` is **exactly consistent** with the proof in §3 Part 2 of `proofs.tex`.

### `circuit_vs_tm.py` — (✓) Correct (2 issues clarified)

All circuit evaluations, depth/size calculations, and TM simulations are correct.

**Bug fixed (v2):** The error message in `circuit_eval` incorrectly suggested `"C_5"` instead of `"C_count_5"` due to `c['name'].split('_')[0]` returning only `"C"`. Fixed to `'_'.join(c['name'].split('_')[:-1])`.

**Naming clarification (v2):** `C_count_N` computes an OR tree (boolean: is any bit 1?) while `M_count_any` counts 1-bits (integer). These are different functions. The naming is intentional for pedagogical purposes — the script demonstrates description *size* growth, not functional equivalence. Cross-function coherence is correctly verified in Part 5 using parity (both circuit and TM compute the same XOR). Documentation note added.

**Abstraction level clarification (v2):** `TM_DESC_SIZES["M_parity_any"] = 4` counts abstract rules (where `q_{.}` covers both `q_even` and `q_odd`). The detailed implementation in `fe_mt_demo.py` uses 6 concrete delta entries. Both are consistent representations at different abstraction levels. Comment added.

### `fe_mt_demo.py` — (✓) Correct

All three TM implementations (`M_count`, `M_parity`, `M_runs`) are formally faithful to the Sipser definition (Q, Σ, Γ, δ, q_0, q_acc). Step-by-step verification on `"1100111"`:
- `M_count = 5` (five 1-bits: `11` and `111`) (✓)
- `M_parity = 1` (XOR: 1^1^0^0^1^1^1 = 1, odd parity) (✓)
- `M_runs = 3` (three contiguous blocks: `11`, `00`, `111`) (✓)

The key invariant — same functional key `sk_M` works for inputs from 4 bits to 1000 bits — is correctly demonstrated for all three machines.

`fe_enc = identity` is explicitly declared as a simulation (Garbled RAM not implemented), consistent with Construction 4.1 in `proofs.tex`.

### Code ↔ `proofs.tex` Coherence — (✓) Consistent

| Claim in `proofs.tex` | Code verification |
|-----------------------|-------------------|
| Dec formula: `Σ cᵢyᵢ - r·sk_y = Σ xᵢyᵢ` | `ipfe_limit.py dec()` — exact match |
| Dim mismatch → IND-CPA break | `ValueError` cases 2, 3, 4 — exact match |
| `id(M) = H(M)` via SHA-256 | `mt_identity()` in `fe_mt_demo.py` — exact match |
| `|sk_M| = poly(λ, |M|)` independent of `|x|` | `mt_desc_size()` constant across all input sizes |
| Garbled RAM = simulation | `fe_enc = identity`, declared in both code and proofs |
| Hybrid argument H_0 to H_q | Structure described in `fe_mt_demo.py` docstrings |
| Punctured key `msk[x*]` | Definition 5.1 in proofs.tex, explained in code README |
| LWE params `n≈1024, q≈2^60` in Setup comment | Illustrative only; real params are `q≈2^100` for 128-bit security |
