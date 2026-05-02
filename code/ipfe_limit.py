"""
ipfe_limit.py — Limite structurelle de l'IPFE (Inner-Product Functional Encryption)
=====================================================================================

CONTEXTE
--------
Ce script illustre pédagogiquement la borne inférieure dimensionnelle de l'IPFE :
une fois le paramètre n (dimension) fixé au Setup, il est IMPOSSIBLE d'évaluer
des produits scalaires sur des vecteurs de dimension n' ≠ n sans tout recommencer.

SOURCES
-------
- Schéma IPFE (version DDH) :
    Abdalla, Bourse, De Caro, Pointcheval.
    "Simple Functional Encryption Schemes for Inner Products."
    PKC 2015. https://link.springer.com/chapter/10.1007/978-3-662-46447-2_33

- Notes pédagogiques sur l'IPFE (ENS Lyon) :
    Damien Stehlé. https://perso.ens-lyon.fr/damien.stehle/IPFE.html

AVERTISSEMENT
-------------
Ce code est PÉDAGOGIQUE, PAS SÉCURISÉ.
Le vrai schéma DDH opère dans un groupe cyclique G d'ordre premier q
dans lequel le logarithme discret est difficile. Ici on simule directement
en Z_p sans exponentielles, ce qui n'offre aucune sécurité.

Dans le vrai schéma DDH-IPFE :
  - Enc publie  c = (g^r, g^{x_1 + r·s_1}, …, g^{x_n + r·s_n})  ∈ G^{n+1}
  - Dec calcule ∏ c_i^{y_i} / c_0^{sk_y} = g^{⟨x,y⟩}
    puis résout le log discret (faisable si ⟨x,y⟩ est petit via BSGS).

Dans ce script, on remplace les exponentielles par l'arithmétique linéaire mod p :
  - c_0 = r  (à la place de g^r)
  - c_i = x_i + r·s_i  mod p  (à la place de g^{x_i + r·s_i})
  - Dec : Σ c_i·y_i - c_0·sk_y mod p  (reproduit exactement ⟨x,y⟩)

STYLE
-----
Style entièrement procédural : chaque schéma est un dictionnaire Python.
  setup(n, p)         → {"n": n, "p": p, "msk": [...]}
  keygen(s, y)        → sk_y  (un entier mod p)
  enc(s, x)           → (c_0, [c_1, …, c_n])   # (n+1)-uplet structuré
  dec(s, sk_y, c, y)  → ⟨x,y⟩ mod p
Ce style rend la structure du schéma visible sans couche d'abstraction objet.
"""

import random


# ─────────────────────────────────────────────────────────────────────────────
# PRIMITIVES DU SCHÉMA IPFE (simulation pédagogique)
# ─────────────────────────────────────────────────────────────────────────────

def setup(n, p):
    """
    Setup(1^λ, n) → schéma s

    Génère la clé maîtresse secrète msk = (s_1, …, s_n) ∈ Z_p^n
    et fixe IRRÉVOCABLEMENT la dimension n.

    Dans Abdalla et al. (DDH) :
        msk = s ∈ Z_p^n  (exposants secrets dans le groupe G)
        mpk = (g, g^{s_1}, …, g^{s_n})  (clé publique, non modélisée ici)

    Ici, on représente le schéma comme un dictionnaire.
    La dimension n est figée dans ce dictionnaire : tout vecteur x ou y
    qui n'est pas de longueur exactement n lèvera une ValueError.
    """
    return {
        "n":   n,
        "p":   p,
        "msk": [random.randint(1, p - 1) for _ in range(n)],
    }


def keygen(s, y):
    """
    KeyGen(msk, y) → sk_y = ⟨msk, y⟩ mod p

    Dans Abdalla et al. (DDH) :
        sk_y = Σ s_i · y_i  mod p
    C'est une combinaison linéaire de la clé maîtresse selon le vecteur y.

    Propriété fonctionnelle : sk_y permet de retrouver ⟨x, y⟩ au
    déchiffrement, mais ne révèle rien d'autre sur x.

    CONTRAINTE : y doit être dans Z_p^n. Si dim(y) ≠ n, le produit scalaire
    ⟨msk, y⟩ n'est pas défini algébriquement, et la clé n'existe pas.
    """
    if len(y) != s["n"]:
        raise ValueError(
            f"[KeyGen] Dimension attendue : {s['n']}, reçue : {len(y)}\n"
            f"  La clé ne peut encoder que des vecteurs de dim {s['n']}.\n"
            f"  Un nouveau Setup(n={len(y)}) est nécessaire."
        )
    return sum(a * b for a, b in zip(s["msk"], y)) % s["p"]


def enc(s, x):
    """
    Enc(mpk, x) → chiffré c = (c_0, [c_1, …, c_n])

    Dans Abdalla et al. (DDH) :
        Tirer r ←$ Z_p*
        c_0 = g^r
        c_i = g^{x_i + r·s_i}  pour i = 1…n
        → c ∈ G^{n+1}  (un (n+1)-uplet dont la structure impose la dimension n)

    Simulation linéaire (sans exponentielles) :
        c_0 = r
        c_i = (x_i + r·s_i)  mod p
    La structure (c_0, [c_1,…,c_n]) est conservée : c_0 joue le rôle de g^r
    et est indispensable au déchiffrement (voir Dec).

    CONTRAINTE : le chiffré est structurellement lié à la dimension n fixée
    au Setup. Un vecteur x' de dimension n' ≠ n produirait un (n'+1)-uplet
    incompatible avec les clés sk_y ∈ Z_p calculées pour n composantes.
    C'est la source de la borne inférieure (cf. proofs.tex, Théorème 3.1).
    """
    if len(x) != s["n"]:
        raise ValueError(
            f"[Enc] Dimension attendue : {s['n']}, reçue : {len(x)}\n"
            f"  → Nouveau Setup(n={len(x)}) obligatoire.\n"
            f"  → Toutes les clés existantes sont invalidées.\n"
            f"  → Ce n'est pas un bug : ⟨x, y⟩ exige dim(x) = dim(y) = n."
        )
    r = random.randint(1, s["p"] - 1)
    # Simulation : c_0 = r,  c_i = x_i + r·s_i  (mod p)
    # Dans le vrai schéma DDH : c_0 = g^r,  c_i = g^{x_i + r·s_i}
    ct = [(xi + r * si) % s["p"] for xi, si in zip(x, s["msk"])]
    return (r, ct)


def dec(s, sk_y, c, y):
    """
    Dec(sk_y, c) → ⟨x, y⟩ mod p

    Dans Abdalla et al. (DDH), le déchiffrement calcule :
        ∏_{i=1}^{n} c_i^{y_i} / c_0^{sk_y}
        = ∏ g^{(x_i + r·s_i)·y_i} / g^{r · Σ s_i·y_i}
        = g^{Σ x_i·y_i + r·Σ s_i·y_i − r·Σ s_i·y_i}
        = g^{⟨x,y⟩}
    puis un log discret final récupère ⟨x,y⟩ (faisable si ⟨x,y⟩ est borné).

    Simulation linéaire (sans exponentielles) :
        c_0 = r,  c_i = x_i + r·s_i  mod p
        Σ c_i·y_i − c_0·sk_y
        = Σ (x_i + r·s_i)·y_i − r · Σ s_i·y_i
        = Σ x_i·y_i + r·Σ s_i·y_i − r·Σ s_i·y_i
        = Σ x_i·y_i  mod p   ✓  (r s'annule exactement)

    REMARQUE : la présence de c_0 dans le chiffré est indispensable.
    Sans lui, r ne peut pas être soustrait et le déchiffrement est incorrect.
    C'est pourquoi enc() retourne un (n+1)-uplet (c_0, [c_1,…,c_n]).
    """
    c0, ct = c
    return (sum(ci * yi for ci, yi in zip(ct, y)) - c0 * sk_y) % s["p"]


# ─────────────────────────────────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 65)
    print("DÉMONSTRATION : Limite structurelle de l'IPFE")
    print("Référence : Abdalla et al. PKC 2015 (schéma DDH-IPFE)")
    print("=" * 65)

    n, p = 4, 104729   # p premier ; n = dimension fixée
    s = setup(n, p)
    print(f"\n[Setup] n = {n} fixé irrévocablement, p = {p}")
    print(f"  msk = {s['msk']}  (exposé ici pour pédagogie, SECRET en pratique)")
    print(f"  Dans le vrai schéma : msk sert à dériver sk_y = <msk, y>")

    # ── CAS 1 : dimension correcte ──────────────────────────────────────────
    print("\n" + "-" * 55)
    print("CAS 1 : x de bonne dimension (n=4) — fonctionnement normal")
    x, y = [12, 15, 9, 7], [1, 1, 1, 0]
    sk_y = keygen(s, y)
    c    = enc(s, x)
    res  = dec(s, sk_y, c, y)
    vrai = sum(a * b for a, b in zip(x, y)) % p
    print(f"  x = {x},  y = {y}")
    print(f"  sk_y = <msk, y> mod p = {sk_y}")
    print(f"  c    = (c_0={c[0]}, ct={c[1]})  [c_0 = r aléatoire, ct masqué par r]")
    print(f"  Dec(sk_y, c)  = {res}")
    print(f"  Valeur attendue ⟨x,y⟩ = {vrai}  {'✅ correct' if res == vrai else '❌ erreur'}")
    print(f"  → Seul ⟨x,y⟩ = {vrai} est révélé, pas x individuellement.")

    # ── CAS 2 : Enc avec vecteur de mauvaise dimension ──────────────────────
    print("\n" + "-" * 55)
    print("CAS 2 : Enc avec x de dimension 5 — Setup pour n=4 incompatible")
    print("  Le chiffré serait un 6-uplet, incompatible avec Dec (n=4 composantes)")
    try:
        enc(s, [12, 15, 9, 7, 3])
    except ValueError as e:
        print(f"  ❌ ValueError levée :")
        for line in str(e).split("\n"):
            print(f"     {line}")

    # ── CAS 3 : KeyGen avec vecteur de mauvaise dimension ───────────────────
    print("\n" + "-" * 55)
    print("CAS 3 : KeyGen avec y de dimension 5 — ⟨msk, y⟩ n'a pas de sens")
    print("  msk ∈ Z_p^4, y ∈ Z_p^5 → Σ msk_i·y_i non défini pour i=5")
    try:
        keygen(s, [1, 1, 1, 1, 1])
    except ValueError as e:
        print(f"  ❌ ValueError levée :")
        for line in str(e).split("\n"):
            print(f"     {line}")

    # ── CAS 4 : nouveau Setup invalide l'ancien schéma ──────────────────────
    print("\n" + "-" * 55)
    print("CAS 4 : nouveau Setup(n=5) — ancien sk_y devient inutilisable")
    s2 = setup(5, p)
    print(f"  Ancien msk (n=4) : {s['msk']}")
    print(f"  Nouveau msk (n=5): {s2['msk']}")
    print(f"  sk_y = {sk_y} a été calculé avec l'ancien msk.")
    print(f"  Avec le nouveau schéma s2, la clé fonctionnelle doit être recalculée.")
    # Vérification : dans s2, le bon sk_y2 pour y=[1,1,1,0] est différent
    y5 = [1, 1, 1, 0, 0]           # y adapté à la nouvelle dimension n=5
    sk_y2 = keygen(s2, y5)
    x5    = [12, 15, 9, 7, 3]
    c5    = enc(s2, x5)
    res5  = dec(s2, sk_y2, c5, y5)
    vrai5 = sum(a * b for a, b in zip(x5, y5)) % p
    print(f"\n  Nouveau schéma s2 utilisé correctement :")
    print(f"    x = {x5}, y = {y5}")
    print(f"    sk_y2 = {sk_y2}  (recalculé avec le nouveau msk)")
    print(f"    Dec(sk_y2, c5) = {res5}  (attendu {vrai5})  "
          f"{'✅ correct' if res5 == vrai5 else '❌ erreur'}")
    print(f"\n  Tentative d'utiliser l'ancien sk_y={sk_y} (dim 4) sur c5 (dim 5) :")
    # Les dimensions de c5[1] (5 éléments) et y (4 éléments) ne correspondent pas.
    # zip tronque silencieusement à 4 termes → résultat incohérent.
    y_old = [1, 1, 1, 0]
    bad   = dec(s2, sk_y, c5, y_old)
    print(f"    Résultat incohérent = {bad}  ≠ {vrai5}  ❌ (sk_y lié à l'ancien msk)")

    print("\n" + "=" * 65)
    print("CONCLUSION")
    print("=" * 65)
    print("""
  ⟨x, y⟩ = Σ x_i·y_i  est défini UNIQUEMENT pour dim(x) = dim(y) = n.

  Conséquences pour des programmes réels :
    - Trier un tableau de taille variable  → ❌ (n change selon l'input)
    - Parser un fichier de taille quelconque → ❌ (idem)
    - Compter des éléments dans un flux     → ❌ (idem)

  En FE : une clé sk_M valable pour toute taille d'input nécessite
  un modèle de calcul dont la DESCRIPTION est constante.
  → Solution : FE pour Machines de Turing  (voir fe_mt_demo.py)
  → Référence : Ananth & Vaikuntanathan, CRYPTO 2021
""")


if __name__ == "__main__":
    demo()
