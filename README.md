# Chiffrement Fonctionnel — De l'IPFE aux Machines de Turing
  
> Auteurs : GS · EB · DO | Mars 2026

---

## Présentation

Le **Chiffrement Fonctionnel (FE)** permet de ne révéler que `f(x)` depuis un chiffré de `x`, sans exposer `x` entier. Ce projet explore la progression naturelle des expressivités :

```
IPFE               →   FE pour Circuits   →   FE pour MT             →   Registered FE/MT
(linéaire, n fixé)     (booléen, n fixé)      (toute MT, |x| ∈ ℕ*)       (sans autorité)
DDH / LWE              LWE (2012)             LWE (2021–22)               LWE (2025)
```

La **limitation structurelle commune** à l'IPFE et aux circuits : la dimension (ou la taille d'entrée) doit être fixée à la construction du schéma. Les Machines de Turing brisent cette contrainte, car leur *description* est constante quelle que soit la taille de l'input.

---

## Structure du projet

```
Projet-FE/
├── README.md                    # Ce fichier
├── code/
│   ├── ipfe_limit.py            # Borne structurelle de l'IPFE (DDH-IPFE, Abdalla et al. PKC 2015)
│   ├── circuit_vs_tm.py         # Circuits booléens vs Machines de Turing (taille de description)
│   └── fe_mt_demo.py            # Simulation FE pour MT : Setup/KeyGen/Enc/Dec
├── proofs/
│   ├── proofs.tex               # Document de preuves formelles (LaTeX)
│   └── proofs.pdf               # Version compilée
├── slides/
│   └── presentation.pptx        # Présentation finale
└── en/
    ├── README.md                # English version of this README
    └── report_en.md             # Full English report (proofs + code analysis)
```

---

## Code — Vue d'ensemble

Les trois scripts sont **pédagogiques** et n'utilisent que la bibliothèque standard Python ≥ 3.8. Aucune installation requise.

```bash
python3 code/ipfe_limit.py
python3 code/circuit_vs_tm.py
python3 code/fe_mt_demo.py
```

### `ipfe_limit.py` — Borne structurelle de l'IPFE

Simule le schéma **DDH-IPFE** d'Abdalla et al. (PKC 2015) en arithmétique linéaire sur Z_p.

Le déchiffrement calcule `Σ cᵢyᵢ − r·sk_y mod p`, ce qui annule exactement le terme aléatoire `r` et donne `⟨x, y⟩`. Quatre cas sont démontrés :
- Cas 1 : fonctionnement normal (dim correcte) → `⟨x, y⟩` récupéré ✅
- Cas 2 : `enc` avec un vecteur de mauvaise dimension → `ValueError`
- Cas 3 : `keygen` avec un vecteur de mauvaise dimension → `ValueError`
- Cas 4 : nouveau `Setup` invalide toutes les clés précédentes

### `circuit_vs_tm.py` — Circuits booléens vs Machines de Turing

Montre quantitativement la différence entre calcul **non-uniforme** (circuits) et **uniforme** (MT) :

| Taille input N | `C_count_N` (FE circuits) | `M_count_any` (FE MT) |
|:--------------:|:-------------------------:|:---------------------:|
| 4              | Θ(4) portes               | 3 règles δ (constant) |
| 100            | Θ(100) portes             | 3 règles δ (constant) |
| 10 000         | Θ(10 000) portes          | 3 règles δ (constant) |

> ⚠️ **Note de cohérence** : `C_count_N` calcule un **OR** (au moins un bit à 1), tandis que `M_count_any` compte le nombre entier de bits à 1. Ces deux fonctions sont intentionnellement différentes — le point clé est la croissance de la *description*, pas la cohérence fonctionnelle. La vérification circuit ↔ MT est faite en Partie 5 avec `C_parity_4` et `tm_parity` (même fonction XOR).

### `fe_mt_demo.py` — Simulation FE pour MT

Simule les quatre algorithmes du schéma FE pour MT d'Ananth & Vaikuntanathan (CRYPTO 2021) :

- `fe_setup()` — génère `(mpk, msk)` (IBE-GPV depuis LWE en pratique, ici registre vide)
- `fe_keygen(registry, M)` — dérive `sk_M = H(M)` comme identité cryptographique IBE
- `fe_enc(x)` — chiffre `x` via Garbled RAM (simulation : identité, pour clarté pédagogique)
- `fe_dec(registry, sk, c)` — exécute `M(x)` via simulation pas-à-pas fidèle à la MT formelle

Trois machines instanciées : `M_count` (compte les 1), `M_parity` (parité XOR), `M_runs` (blocs contigus). La même clé fonctionnelle est utilisée pour des inputs de 4 bits à 1000 bits.

---

## Preuves (`proofs/proofs.tex`)

Le document couvre quatre résultats, chacun précédé d'une **boîte Intuition** :

1. **Borne inférieure de l'IPFE** (§3) — preuve par l'absurde : un mécanisme de conversion hypothétique entre dimensions casserait IND-CPA.
2. **Difficulté de LWE** (§2.10) — rôle du bruit, réduction de Regev (STOC 2005) : GapSVP difficile → LWE difficile → résistance post-quantique.
3. **FE pour MT — sécurité sélective** (§4) — construction IBE-LWE + Garbled RAM, preuve par hybrid argument en `q` jeux.
4. **Sécurité adaptive via Punctured Programming** (§5) — clé percée `msk[x*]` et évaluation FHE à l'aveugle.

### Compilation

```bash
cd proofs
pdflatex proofs.tex && pdflatex proofs.tex
```

---

## Vérification : code ↔ preuves

| Élément du code | Correspondance dans `proofs.tex` |
|----------------|----------------------------------|
| `dec()` : `Σ cᵢyᵢ − c₀·sk_y mod p` | Partie 2 de la preuve Thm 3.1 (simulation linéaire DDH) |
| `ValueError` sur dim. incorrecte | Partie 1 & 3 de la preuve Thm 3.1 (absurde IND-CPA) |
| `mt_identity(M) = H(M)` | Construction 4.1, KeyGen : `sk_M ← IBE.KeyGen(msk, H(M))` |
| `fe_enc = identité` | Construction 4.1 Enc : simulation déclarée (Garbled RAM non implémenté) |
| Hybrid argument `H_0 … H_q` | Preuve Thm 4.1, jeux hybrides gamebox |
| `msk[x*]` (clé percée) | Définition 5.1 + preuve Thm 5.1 |

---

## Références principales

| Résultat | Référence |
|----------|-----------|
| DDH-IPFE | Abdalla, Bourse, De Caro, Pointcheval — PKC 2015 |
| FE pour circuits | Gorbunov, Vaikuntanathan, Wee — CRYPTO 2012 |
| LWE & réduction GapSVP | Regev — STOC 2005 / JACM 2009 |
| IBE depuis LWE (GPV) | Gentry, Peikert, Vaikuntanathan — STOC 2008 |
| Garbled RAM | Lu, Ostrovsky — EUROCRYPT 2013 |
| FE pour MT (sélectif) | Ananth, Vaikuntanathan — CRYPTO 2021 |
| FE pour MT (adaptatif) | Agrawal, Feng, Sarkar, Yadav — ASIACRYPT 2022 |
| Registered FE pour MT | IACR ePrint 2025/967 |
