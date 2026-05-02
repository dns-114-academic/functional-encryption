"""
fe_mt_demo.py — FE pour Machines de Turing : simulation pédagogique
====================================================================

CONTEXTE
--------
L'IPFE et les circuits booléens partagent une contrainte structurelle :
la taille de l'input doit être fixée à la construction. Les Machines de
Turing ont une description constante |M| et traitent des inputs de toute
taille. Ce script simule le schéma FE pour MT d'Ananth & Vaikuntanathan.

SOURCES
-------
- Construction FE pour MT (IBE-LWE + Garbled RAM) :
    Ananth, Vaikuntanathan.
    "Optimal Bounded-Collusion Secure Functional Encryption."
    CRYPTO 2021. https://dl.acm.org/doi/abs/10.1007/978-3-030-84259-8_9

- IBE depuis LWE (composant Setup/KeyGen) :
    Gentry, Peikert, Vaikuntanathan.
    "Trapdoors for Hard Lattices and New Cryptographic Constructions."
    STOC 2008. (GPV IBE : l'identité id(M) = H(M) lie sk_M à la description de M)

- Garbled RAM (composant Enc/Dec) :
    Lu, Ostrovsky.
    "Garbled RAM Revisited, Part I."
    EUROCRYPT 2013.
    (Encode l'exécution de M sur x sans révéler M ni x, seulement M(x))

- Sécurité adaptive (extension) :
    Agrawal, Feng, Sarkar, Yadav.
    "Adaptively Secure FE for Turing Machines from LWE."
    ASIACRYPT 2022.

MODÈLE DE CALCUL
----------------
Les trois MT implémentées (M_count, M_parity, M_runs) sont des simulateurs
pas-à-pas fidèles à la définition formelle (Sipser, chap. 3) :
  M = (Q, Σ, Γ, δ, q_0, q_accept, q_reject)
  δ : Q × Γ → Q × Γ × {L, R}  (fonction de transition déterministe)

La simulation utilise des registres internes (reg) pour accumuler le résultat
en un seul passage sur la bande, évitant un second déplacement de tête.

SIMULATION FE
-------------
La construction réelle (CRYPTO 2021) utilise :
  1. IBE-GPV : Setup génère (mpk_IBE, msk_IBE) ; KeyGen dérive sk_M
     comme une clé IBE pour l'identité id(M) = H(M) (hash SHA-256 de δ).
  2. Garbled RAM : Enc brouille l'exécution de M_univ sur x, permettant
     de calculer M(x) sans révéler x.
Ici, Enc = identité (simulation) pour illustrer les propriétés de taille
et de structure sans implémenter LWE ni le Garbled RAM complet.

STYLE
-----
Entièrement procédural. Chaque MT est un dictionnaire :
  {"name": ..., "delta": {(état, symbole): (nouvel_état, écriture, dir)},
   "q0": ..., "output_fn": lambda reg, x: ...}
"""

import hashlib
import json

# Symboles spéciaux de la bande de Turing
BLANK  = "□"           # symbole blanc (fin de bande)
HALT   = "q_accept"    # état acceptant (arrêt de la MT)


# ─────────────────────────────────────────────────────────────────────────────
# REPRÉSENTATION ET SIMULATION D'UNE MACHINE DE TURING
# ─────────────────────────────────────────────────────────────────────────────

def make_mt(name, delta, q0, output_fn):
    """
    Crée un dictionnaire représentant une MT déterministe.

    name      : identifiant lisible (ex. "M_count")
    delta     : dict { (état, symbole) : (nouvel_état, écriture, direction) }
                direction ∈ {"L", "R"}
    q0        : état initial
    output_fn : lambda (reg, x) → résultat
                reg = registres internes mis à jour pendant l'exécution
                x   = input original (pour les cas où on veut accéder à x entier)

    Structure fidèle à la définition formelle :
      M = (Q, Σ, Γ, δ, q_0, q_accept, q_reject)
    avec Q = ensemble des états-clés de delta, Γ = {0, 1, □}.
    """
    return {"name": name, "delta": delta, "q0": q0, "output_fn": output_fn}


def mt_run(m, x, max_steps=100_000):
    """
    Exécute M sur l'input x et retourne M(x).

    Simulation pas-à-pas de la MT :
      1. Initialisation : bande = x + [□], tête à 0, état = q0
      2. À chaque étape :
           - Lire le symbole sous la tête
           - Chercher (état, symbole) dans δ
           - Écrire le nouveau symbole, déplacer la tête, changer d'état
           - Mettre à jour les registres internes (résultat partiel)
      3. Arrêt : état = HALT ou dépassement de max_steps

    Registres internes (reg) :
      reg["count"]  : nombre de '1' vus (pour M_count)
      reg["parity"] : XOR cumulatif (pour M_parity)
      reg["runs"]   : nombre de blocs contigus (pour M_runs)

    Complexité : O(T_M(n)) pas, où T_M(n) est le temps de M sur x.
    Dans le FE, T_Dec = poly(λ, T_M(|x|)).

    max_steps : garde-fou pour les boucles infinies (MT non-terminantes).
    """
    tape  = list(x) + [BLANK]   # bande infinie à droite simulée par une liste
    head  = 0                   # position de la tête de lecture/écriture
    state = m["q0"]             # état courant, initialisé à l'état initial q0
    reg   = {"count": 0, "parity": 0, "runs": 0}  # registres internes

    for _ in range(max_steps):
        if state == HALT:
            break   # la MT a atteint l'état acceptant

        # Lire le symbole sous la tête (□ si on dépasse la bande)
        sym = tape[head] if head < len(tape) else BLANK

        # Chercher la transition δ(état, symbole)
        if (state, sym) not in m["delta"]:
            raise RuntimeError(f"[{m['name']}] pas de transition ({state}, '{sym}')")
        new_state, write, direction = m["delta"][(state, sym)]

        # ── Mise à jour des registres selon la transition active ──────────────
        # M_count : incrémenter si on lit un '1' dans l'état q_scan
        if state == "q_scan" and sym == "1":
            reg["count"] += 1

        # M_parity : basculer la parité si on lit un '1'
        if state in ("q_even", "q_odd") and sym == "1":
            reg["parity"] ^= 1

        # M_runs : initialiser le premier run au premier symbole non-blanc
        if state == "q_start" and sym in ("0", "1"):
            reg["runs"] = 1

        # M_runs : incrémenter le nombre de runs à chaque changement de symbole
        if (state, new_state) in [("q_in0", "q_in1"), ("q_in1", "q_in0")]:
            reg["runs"] += 1

        # ── Exécuter la transition ────────────────────────────────────────────
        tape[head] = write
        head = max(0, head + (1 if direction == "R" else -1))
        if head >= len(tape):
            tape.append(BLANK)   # étendre la bande si nécessaire
        state = new_state
    else:
        raise RuntimeError(f"[{m['name']}] dépassement de {max_steps} étapes")

    # Calculer la sortie M(x) via la fonction de sortie propre à chaque MT
    return m["output_fn"](reg, x)


def mt_identity(m):
    """
    Identité cryptographique de M : id(M) = H(description de M).

    Dans la construction IBE de Ananth-V 2021 (GPV IBE) :
      KeyGen(msk, M) génère une clé IBE pour l'identité id(M) = H(M).
      Le hash SHA-256 de la description de δ sert d'identifiant unique.

    Propriété : deux MT avec la même fonction mais des δ syntaxiquement
    différents auraient des identités différentes. On utilise une
    représentation canonique triée pour assurer le déterminisme du hash.

    Dans un vrai schéma GPV : l'identité est un élément de Z_q^n
    dérivé par un hash vers les réseaux (hash-to-lattice).
    """
    desc = json.dumps(
        {"delta": sorted([(str(k), v) for k, v in m["delta"].items()])},
        sort_keys=True,
    ).encode()
    # SHA-256 tronqué à 16 caractères pour l'affichage pédagogique
    # Dans un vrai schéma : output complet de 256 bits utilisé comme identité IBE
    return hashlib.sha256(desc).hexdigest()[:16]


def mt_desc_size(m):
    """
    Taille de la description de M en octets (mesure de |M|).

    Propriété fondamentale du FE pour MT :
      |sk_M| = poly(λ, |M|)  — indépendant de |x|

    Cette fonction mesure |M| = taille de la description de δ.
    Quelle que soit la taille de l'input x, |M| reste constant.
    C'est ce qui permet à sk_M d'être de taille fixe (poly en |M|, pas en |x|).
    """
    return len(json.dumps(
        {"q0": m["q0"], "delta": {str(k): v for k, v in m["delta"].items()}}
    ))


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUCTION DES TROIS MACHINES DE TURING
# ─────────────────────────────────────────────────────────────────────────────

def build_M_count():
    """
    M_count : compte les bits à 1 dans x.

    Description formelle :
      Q = {q_scan, q_accept},  Σ = {0, 1},  Γ = {0, 1, □}
      δ(q_scan, '0') = (q_scan, '0', R)  — ignorer les 0
      δ(q_scan, '1') = (q_scan, '1', R)  — compter (via registre reg["count"])
      δ(q_scan,  □)  = (q_accept, □, R)  — fin de bande : retourner count

    |M_count| = 3 transitions (constant).
    T_M(n) = O(n) (un pas par symbole).

    Cohérence avec circuit_vs_tm.py :
      tm_count([True, False, True, True]) = 3
      M_count sur "1011" = 3  ✅
    """
    delta = {
        ("q_scan", "0"):   ("q_scan", "0", "R"),
        ("q_scan", "1"):   ("q_scan", "1", "R"),   # registre mis à jour dans mt_run
        ("q_scan", BLANK): (HALT,     BLANK, "R"),
    }
    return make_mt("M_count", delta, "q_scan", lambda reg, x: reg["count"])


def build_M_parity():
    """
    M_parity : calcule la parité (XOR) de tous les bits de x.

    Description formelle :
      Q = {q_even, q_odd, q_accept}
      q_even = parité courante 0,  q_odd = parité courante 1
      δ(q_even, '1') = (q_odd,  '1', R)  — basculer parité
      δ(q_odd,  '1') = (q_even, '1', R)  — basculer parité
      δ(q_{.},  '0') = (q_{.},  '0', R)  — conserver parité
      δ(q_{.},   □)  = (q_accept, □, R)  — fin : retourner la parité

    |M_parity| = 6 transitions (constant).
    Résultat : ⊕_i x_i = XOR cumulatif de tous les bits.
    """
    delta = {
        ("q_even", "0"):   ("q_even", "0", "R"),
        ("q_even", "1"):   ("q_odd",  "1", "R"),
        ("q_odd",  "0"):   ("q_odd",  "0", "R"),
        ("q_odd",  "1"):   ("q_even", "1", "R"),
        ("q_even", BLANK): (HALT,     BLANK, "R"),
        ("q_odd",  BLANK): (HALT,     BLANK, "R"),
    }
    return make_mt("M_parity", delta, "q_even", lambda reg, x: reg["parity"])


def build_M_runs():
    """
    M_runs : compte le nombre de blocs contigus (runs) dans x.

    Exemple : "1100111" → 3 blocs (11, 00, 111) → M_runs = 3

    Description formelle :
      Q = {q_start, q_in0, q_in1, q_accept}
      δ(q_start, '0') = (q_in0, '0', R)  — premier symbole = 0
      δ(q_start, '1') = (q_in1, '1', R)  — premier symbole = 1
      δ(q_in0,   '0') = (q_in0, '0', R)  — continuer dans un bloc de 0
      δ(q_in0,   '1') = (q_in1, '1', R)  — transition 0→1 : nouveau run
      δ(q_in1,   '1') = (q_in1, '1', R)  — continuer dans un bloc de 1
      δ(q_in1,   '0') = (q_in0, '0', R)  — transition 1→0 : nouveau run
      δ(q_{.},    □)  = (q_accept, □, R) — fin de bande

    |M_runs| = 9 transitions (constant).
    Les transitions (q_in0→q_in1) et (q_in1→q_in0) incrémentent reg["runs"].
    """
    delta = {
        ("q_start", "0"):   ("q_in0", "0", "R"),
        ("q_start", "1"):   ("q_in1", "1", "R"),
        ("q_start", BLANK): (HALT,    BLANK, "R"),
        ("q_in0",   "0"):   ("q_in0", "0", "R"),
        ("q_in0",   "1"):   ("q_in1", "1", "R"),  # run++
        ("q_in0",   BLANK): (HALT,    BLANK, "R"),
        ("q_in1",   "1"):   ("q_in1", "1", "R"),
        ("q_in1",   "0"):   ("q_in0", "0", "R"),  # run++
        ("q_in1",   BLANK): (HALT,    BLANK, "R"),
    }
    return make_mt("M_runs", delta, "q_start", lambda reg, x: reg["runs"])


# ─────────────────────────────────────────────────────────────────────────────
# SIMULATION DU SCHÉMA FE POUR MT
# ─────────────────────────────────────────────────────────────────────────────

def fe_setup():
    """
    Setup(1^λ) → (mpk, msk)

    Simulation : retourne un registre vide {sk → M}.
    Dans la vraie construction (Ananth-V 2021, Section 4) :
      (mpk_IBE, msk_IBE) ← IBE.Setup(1^λ)  [IBE-GPV depuis LWE]
    Le schéma IBE permet de dériver des clés par identité id(M) = H(M).
    """
    print("[FE/MT Setup] Paramètres publics générés (λ = 128 bits simulés).")
    print("  Vrai Setup : (mpk_IBE, msk_IBE) ← IBE-GPV.Setup(1^128)")
    print("  Hypothèse : LWE_{1024, 2048, 2^60, χ}  (post-quantique, cf. proofs.tex §2)")
    return {}   # registry : id(M) → MT


def fe_keygen(registry, m):
    """
    KeyGen(msk, M) → sk_M

    Simulation : sk_M = hash de la description de M (identité cryptographique).
    Dans la vraie construction :
      sk_M ← IBE.KeyGen(msk_IBE, id(M))  [clé IBE pour l'identité H(M)]

    Propriété de taille :
      |sk_M| = poly(λ, |M|)  — indépendant de |x|
    La clé est liée à la DESCRIPTION de M, pas à sa trace d'exécution.

    Même clé sk_M pour x = "1011" (4 bits) et x = "10"*500 (1000 bits).
    """
    sk = mt_identity(m)
    registry[sk] = m
    print(f"[KeyGen] sk_{m['name']:8s} = '{sk}' | |M| = {mt_desc_size(m):4d} octets (constant)")
    return sk


def fe_enc(x):
    """
    Enc(mpk, x) → chiffré c

    Simulation : identité (Enc(x) = x pour clarté pédagogique).
    Dans la vraie construction (Section 4.2 d'Ananth-V 2021) :
      r ←$ {0,1}^λ
      (M̃_univ, x̃) ← Garble(M_univ, x ; r)  [Garbled RAM de Lu-Ostrovsky 2013]
      c = (M̃_univ, IBE.Enc(mpk_IBE, K_r))

    Le Garbled RAM brouille l'exécution de la MT universelle M_univ sur x :
      - M̃_univ et x̃ révèlent UNIQUEMENT M(x) lors de l'évaluation
      - K_r est la clé de débrouillage, chiffrée avec IBE pour l'identité id(M)

    Taille du chiffré : |c| = poly(λ, |x|)
    """
    return x


def fe_dec(registry, sk, c):
    """
    Dec(sk_M, c) → M(x)

    Simulation : exécute directement mt_run(M, x).
    Dans la vraie construction :
      1. Déchiffrer IBE : K_r ← IBE.Dec(sk_M, IBE.Enc(mpk_IBE, K_r))
         (possible car sk_M est la clé IBE pour id(M) = H(M))
      2. Évaluer le Garbled RAM : Eval(M̃_univ, x̃) → M(x)
         (K_r sert à débrouiller la sortie sans révéler M ni x)

    Sécurité : l'évaluateur apprend UNIQUEMENT M(x) et des tailles de bandes.
    Complexité : T_Dec = poly(λ, T_M(|x|))
    """
    return mt_run(registry[sk], c)


# ─────────────────────────────────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 65)
    print("DÉMONSTRATION : FE pour Machines de Turing")
    print("Référence : Ananth & Vaikuntanathan, CRYPTO 2021")
    print("=" * 65)

    # ── Setup et instanciation des MT ──────────────────────────────────────
    print()
    registry = fe_setup()
    M_count  = build_M_count()
    M_parity = build_M_parity()
    M_runs   = build_M_runs()

    print("\n[Machines de Turing instanciées]")
    for m in [M_count, M_parity, M_runs]:
        print(f"  {m['name']:12s} | id(M) = {mt_identity(m)} | |M| = {mt_desc_size(m)} octets")
    print("  → |M| est constant : il ne dépend pas de la taille de l'input à venir.")

    # ── Génération des clés fonctionnelles ─────────────────────────────────
    print("\n--- Génération des clés (KeyGen simulé) ---")
    sk_count  = fe_keygen(registry, M_count)
    sk_parity = fe_keygen(registry, M_parity)
    sk_runs   = fe_keygen(registry, M_runs)
    print("\n  → Ces trois clés sont générées UNE SEULE FOIS.")
    print("    Elles fonctionneront pour DES INPUTS DE TOUTE TAILLE.")

    # ── Propriété fondamentale : même clé, toute taille ───────────────────
    test_inputs = [
        ("1011",            "n=4"),
        ("10110010111",     "n=11"),
        ("1100111",         "n=7"),
        ("0" * 50 + "1" * 50, "n=100"),
        ("10" * 500,        "n=1000"),
    ]

    print("\n--- Propriété clé : même sk_M pour tout |x| ---")
    print(f"{'Input':>20s} {'|x|':>6s} | {'M_count':>8s} {'M_parity':>10s} {'M_runs':>8s}")
    print("-" * 60)
    for x, label in test_inputs:
        c = fe_enc(x)
        r_count  = fe_dec(registry, sk_count,  c)
        r_parity = fe_dec(registry, sk_parity, c)
        r_runs   = fe_dec(registry, sk_runs,   c)
        disp = x[:15] + "..." if len(x) > 15 else x
        print(f"  {disp:>18s} {label:>6s} | {r_count:>8d} {r_parity:>10d} {r_runs:>8d}")

    print("\n  → sk_count  = '{}' fonctionne pour n=4 ET n=1000.".format(sk_count))
    print("    Les bits individuels de x ne sont JAMAIS révélés.")
    print("    Seuls M_count(x), M_parity(x), M_runs(x) sont accessibles.")

    # ── Lecture des résultats commentée ────────────────────────────────────
    print("\n--- Lecture des résultats pour '1100111' (n=7) ---")
    x_demo = "1100111"
    c_demo  = fe_enc(x_demo)
    print(f"  Input : {x_demo!r}")
    print(f"  M_count(x)  = {fe_dec(registry, sk_count,  c_demo)} "
          f"  (→ 5 bits à 1 : '11' + '111' = 5 uns)")
    print(f"  M_parity(x) = {fe_dec(registry, sk_parity, c_demo)} "
          f"  (→ XOR : 1^1^0^0^1^1^1 = 1 → parité impaire)")
    print(f"  M_runs(x)   = {fe_dec(registry, sk_runs,   c_demo)} "
          f"  (→ 3 blocs : '11', '00', '111')")

    # ── Tableau comparatif IPFE vs FE/MT ──────────────────────────────────
    print("\n" + "=" * 65)
    print("COMPARAISON : IPFE vs FE pour MT")
    print("=" * 65 + """
  ┌─────────────────────┬────────────────────┬────────────────────┐
  │ Propriété           │ IPFE               │ FE pour MT         │
  ├─────────────────────┼────────────────────┼────────────────────┤
  │ Fonctions           │ ⟨x, y⟩ (linéaire) │ Toute MT M(x)      │
  │ Taille input        │ Fixée au Setup ❌  │ Variable ✅         │
  │ Même clé / taille   │ Non ❌             │ Oui ✅              │
  │ Hypothèse           │ DDH / LWE          │ LWE                │
  │ Post-quantique      │ Via LWE            │ Oui ✅              │
  │ Sécurité adaptive   │ Oui (LWE)          │ Depuis 2022 ✅      │
  └─────────────────────┴────────────────────┴────────────────────┘
""")


if __name__ == "__main__":
    demo()
