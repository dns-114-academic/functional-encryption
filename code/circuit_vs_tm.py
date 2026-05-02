"""
circuit_vs_tm.py — Circuit booléen vs Machine de Turing pour le FE
===================================================================

CONTEXTE
--------
L'IPFE est limité aux fonctions linéaires sur des vecteurs de dimension fixe.
Une généralisation naturelle est le FE pour circuits booléens (Gorbunov et al.
CRYPTO 2012) : on peut évaluer n'importe quelle fonction booléenne, mais
un circuit a un nombre d'entrées fixé à sa construction — exactement comme l'IPFE.

Ce script montre quantitativement cette limitation :
  - C_count_n doit être reconstruit pour chaque n (taille Θ(n) portes)
  - Une MT M_count a une description CONSTANTE (3 règles δ) pour tout n

La différence est celle entre calcul NON-UNIFORME (circuits : description
différente par taille) et calcul UNIFORME (MT : un seul programme).

SOURCES
-------
- FE pour circuits booléens :
    Gorbunov, Vaikuntanathan, Wee.
    "Functional Encryption with Bounded Collusions via Multi-Party Computation."
    CRYPTO 2012. https://link.springer.com/chapter/10.1007/978-3-642-32009-5_30

- Circuits booléens (définitions formelles) :
    Sipser, "Introduction to the Theory of Computation", chap. 9.
    Arora & Barak, "Computational Complexity: A Modern Approach", chap. 6.

- Machines de Turing (construction des δ utilisées ici) :
    Sipser, chap. 3 — construction standard du simulateur pas-à-pas.

STYLE
-----
Entièrement procédural. Chaque circuit est un dictionnaire :
  {"n": n, "gates": [...], "output_idx": k, "name": "C_count_4"}
Chaque porte est un dictionnaire :
  {"op": "AND"|"OR"|"XOR"|"NOT"|"INPUT", "idx": i, "inputs": [...]}
La MT est représentée par une fonction Python pure (voir fe_mt_demo.py
pour la version dictionnaire complète utilisée dans la construction FE).
"""


# ─────────────────────────────────────────────────────────────────────────────
# REPRÉSENTATION DES CIRCUITS BOOLÉENS
# ─────────────────────────────────────────────────────────────────────────────

def gate(op, idx, inputs=()):
    """
    Crée un nœud (porte) du DAG représentant le circuit.

    op      : "INPUT", "AND", "OR", "XOR", "NOT"
    idx     : indice unique de cette porte dans la liste gates[]
    inputs  : indices des portes dont la sortie est l'entrée de celle-ci

    Structure DAG : les portes INPUT ont inputs=() (feuilles du DAG).
    Les portes AND/OR/XOR ont exactement deux inputs ; NOT en a un seul.
    """
    return {"op": op, "idx": idx, "inputs": list(inputs)}


def circuit(n, gates, output_idx, name="C"):
    """
    Crée un circuit booléen.

    n          : nombre exact d'entrées (FIXÉ À LA CONSTRUCTION)
    gates      : liste ordonnée de dicts gate(), topologiquement triée
                 (les portes INPUT précèdent toujours les portes logiques)
    output_idx : indice dans gates[] de la porte de sortie
    name       : nom du circuit (convention : C_<fonction>_<n>)

    Complexité :
      taille  |C| = nombre de portes non-INPUT
      profondeur d(C) = longueur du plus long chemin INPUT → output
    """
    return {"n": n, "gates": gates, "output_idx": output_idx, "name": name}


def circuit_size(c):
    """Nombre de portes logiques (hors INPUT) = mesure de complexité du circuit."""
    return sum(1 for g in c["gates"] if g["op"] != "INPUT")


def circuit_depth(c):
    """
    Profondeur du circuit = longueur du plus long chemin de la source à la sortie.
    Calculée par programmation dynamique en un seul passage (le DAG est trié).
    """
    d = [0] * len(c["gates"])
    for g in c["gates"]:
        if g["op"] != "INPUT":
            # La profondeur de cette porte = 1 + max des profondeurs de ses entrées
            d[g["idx"]] = 1 + max(d[i] for i in g["inputs"])
    return d[c["output_idx"]]


def circuit_eval(c, bits):
    """
    Évalue le circuit c sur l'entrée bits (liste de booléens).

    Algorithme : balayage linéaire du DAG dans l'ordre topologique.
    La valeur de chaque porte est stockée dans vals[].
    Complexité : O(|C|) en temps.

    CONTRAINTE : len(bits) doit être exactement c["n"].
    Si bits a une longueur différente, l'évaluation est IMPOSSIBLE :
    il n'existe pas de mécanisme de compatibilité entre circuits de
    tailles différentes (analogue à la contrainte de dimension dans l'IPFE).
    """
    if len(bits) != c["n"]:
        raise ValueError(
            f"[Circuit {c['name']}] taille d'entrée incorrecte :\n"
            f"  Attendu : {c['n']} bits  —  Reçu : {len(bits)} bits\n"
            f"  → Ce circuit ne peut PAS traiter cet input.\n"
            f"  → Il faudrait construire {'_'.join(c['name'].split('_')[:-1])}_{len(bits)}."
        )
    vals = [None] * len(c["gates"])

    # Passe 1 : affecter les valeurs d'entrée aux portes INPUT
    for g in c["gates"]:
        if g["op"] == "INPUT":
            vals[g["idx"]] = bits[g["idx"]]

    # Passe 2 : calculer chaque porte dans l'ordre topologique
    for g in c["gates"]:
        if g["op"] == "INPUT":
            continue
        v = [vals[i] for i in g["inputs"]]
        if   g["op"] == "AND": vals[g["idx"]] = all(v)
        elif g["op"] == "OR":  vals[g["idx"]] = any(v)
        elif g["op"] == "XOR": vals[g["idx"]] = v[0] ^ v[1]
        elif g["op"] == "NOT": vals[g["idx"]] = not v[0]

    return vals[c["output_idx"]]


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUCTEURS DE CIRCUITS
# ─────────────────────────────────────────────────────────────────────────────

def build_count_circuit(n):
    """
    C_count_n : teste si au moins un bit est à 1 (arbre d'OR).

    Construction : arbre binaire de portes OR sur les n entrées.
      - Taille : Θ(n) portes  →  croît LINÉAIREMENT avec n.
      - Profondeur : Θ(log n).

    Pour FE (Gorbunov-VW 2012) :
      sk_{C_count_4} est inutilisable pour des inputs de 5 bits.
      Il faut générer une nouvelle clé sk_{C_count_5} depuis un nouveau circuit.

    NOTE DE COHÉRENCE : ce circuit est nommé C_count mais calcule un OR (booléen).
      tm_count (fe_mt_demo.py) calcule le nombre entier de 1. Ce sont deux fonctions
      différentes — le choix est délibéré pour montrer que même pour des fonctions
      distinctes, la TAILLE DU CIRCUIT croît en Θ(n) et la DESCRIPTION DE LA MT
      reste constante. La cohérence fonctionnelle circuit↔MT est vérifiée en
      Partie 5 avec C_parity / tm_parity, qui calculent tous les deux le même XOR.
    """
    gates = [gate("INPUT", i) for i in range(n)]
    layer, idx = list(range(n)), n
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                gates.append(gate("OR", idx, [layer[i], layer[i + 1]]))
                next_layer.append(idx)
                idx += 1
            else:
                next_layer.append(layer[i])   # nœud seul : passe à la couche suivante
        layer = next_layer
    return circuit(n, gates, layer[0], f"C_count_{n}")


def build_parity_circuit(n):
    """
    C_parity_n : calcule le XOR de tous les n bits (parité).

    Construction : arbre binaire de portes XOR.
      - Taille : Θ(n),  profondeur : Θ(log n).

    Utilisé pour vérifier la cohérence circuit ↔ MT :
    le circuit C_parity_4 et la MT M_parity doivent donner le même résultat
    sur tout input de 4 bits (voir partie 5 de demo()).
    """
    gates = [gate("INPUT", i) for i in range(n)]
    layer, idx = list(range(n)), n
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                gates.append(gate("XOR", idx, [layer[i], layer[i + 1]]))
                next_layer.append(idx)
                idx += 1
            else:
                next_layer.append(layer[i])
        layer = next_layer
    return circuit(n, gates, layer[0], f"C_parity_{n}")


# ─────────────────────────────────────────────────────────────────────────────
# MACHINES DE TURING ÉQUIVALENTES
# Description CONSTANTE, indépendante de la taille de l'input.
# ─────────────────────────────────────────────────────────────────────────────

def tm_count(bits):
    """
    M_count_any : compte les bits à 1 — toute taille d'input.

    Description formelle de la MT (δ explicite) :
      États : {q_scan, q_accept}
      Σ = {0, 1},  Γ = {0, 1, □}
      δ(q_scan, '0') = (q_scan, '0', R)   — ignorer les 0
      δ(q_scan, '1') = (q_scan, '1', R)   — compter les 1 (registre interne)
      δ(q_scan,  □)  = (q_accept, □, R)   — fin de bande : retourner le compte

    Taille de description : |M| = 3 transitions (CONSTANTE pour tout |x|).
    Complexité temporelle : T_M(n) = O(n).

    Dans FE pour MT (Ananth-V 2021) :
      sk_M est lié à H(description de M), indépendant de |x|.
      La même sk_{M_count} déchiffre Enc(x) pour tout |x|.
    """
    return sum(1 for b in bits if b)


def tm_parity(bits):
    """
    M_parity_any : calcule la parité de x — toute taille d'input.

    Description formelle de la MT :
      États : {q_even, q_odd, q_accept}  (q_even = parité courante est 0)
      δ(q_even, '1') = (q_odd,  '1', R)  — basculer parité
      δ(q_odd,  '1') = (q_even, '1', R)  — basculer parité
      δ(q_even, '0') = (q_even, '0', R)  — conserver
      δ(q_odd,  '0') = (q_odd,  '0', R)  — conserver
      δ(q_{.},   □)  = (q_accept, □, R)  — retourner la parité

    Taille de description : |M| = 4 transitions (CONSTANTE).
    Résultat : ⊕_i x_i = XOR cumulatif des bits.
    """
    p = 0
    for b in bits:
        p ^= int(b)
    return p


# Tailles de description (nombre de règles de transition δ)
# M_count_any  : 3 règles concrètes (cohérent avec fe_mt_demo.py : 3 entrées dans delta).
# M_parity_any : 4 règles ABSTRAITES (q_{.} couvre q_even et q_odd pour '0' et □).
#                En transitions concrètes : 6 entrées (voir fe_mt_demo.py build_M_parity).
#                Les deux comptages sont corrects à des niveaux d abstraction différents.
TM_DESC_SIZES = {"M_count_any": 3, "M_parity_any": 4}


# ─────────────────────────────────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 70)
    print("DÉMONSTRATION : Circuit booléen vs Machine de Turing")
    print("FE circuits : Gorbunov-Vaikuntanathan-Wee, CRYPTO 2012")
    print("FE pour MT  : Ananth-Vaikuntanathan, CRYPTO 2021")
    print("=" * 70)

    # ── Partie 1 : circuits de taille croissante ──────────────────────────────
    print("\n--- Circuits C_count_n : taille Θ(n), description différente par n ---")
    circuits = {}
    print(f"\n  {'n':>5s}  {'Nom':>15s}  {'Taille (|C|)':>13s}  {'Profondeur':>11s}")
    print("  " + "-" * 50)
    for n in [4, 5, 8, 16, 100]:
        c = build_count_circuit(n)
        circuits[n] = c
        print(f"  {n:>5d}  {c['name']:>15s}  {circuit_size(c):>13d}  {circuit_depth(c):>11d}")
    print(f"\n  → Pour FE, il faut UNE CLÉ DIFFÉRENTE sk_{{C_n}} pour chaque n.")
    print(f"  → La taille du circuit croît linéairement : même limitation que l'IPFE.")

    # ── Partie 2 : erreur si mauvaise dimension ───────────────────────────────
    print("\n--- Erreur de dimension : incompatibilité inter-tailles ---")
    bits4 = [True, False, True, True]
    bits5 = [True, False, True, True, False]
    res4 = circuit_eval(circuits[4], bits4)
    print(f"\n  C_count_4 sur input de 4 bits : {res4}  ✅")
    print(f"\n  C_count_4 sur input de 5 bits :")
    try:
        circuit_eval(circuits[4], bits5)
    except ValueError as e:
        for line in str(e).split("\n"):
            print(f"    {line}")
    print("\n  → Même limitation que l'IPFE : la taille de l'input est figée.")

    # ── Partie 3 : MT avec description constante ─────────────────────────────
    print("\n--- MT M_count_any : description constante (3 règles δ), toute taille ---")
    print(f"\n  |M_count_any| = {TM_DESC_SIZES['M_count_any']} règles δ — CONSTANT pour tout |x|")
    print(f"\n  {'|x|':>8s}  {'M_count(x)':>12s}")
    print("  " + "-" * 22)
    for bits in [
        [True, False, True, True],
        [True, False, True, True, False],
        [True, False] * 4,
        [True] * 8 + [False] * 8,
        [i % 3 == 0 for i in range(100)],
        [i % 7 != 0 for i in range(10_000)],
    ]:
        print(f"  {len(bits):>8d}  {tm_count(bits):>12d}  ✅")

    print("\n  → La MÊME clé fonctionnelle sk_{M_count} déchiffre pour tout |x|.")
    print("    En FE pour MT, |sk_M| = poly(λ, |M|) — indépendant de |x|.")

    # ── Partie 4 : tableau comparatif ────────────────────────────────────────
    print("""
--- Comparaison : complexité de description pour f_count ---

  ┌────────────┬──────────────────────┬──────────────────────┐
  │ |x| = N    │ Circuit C_count_N    │ MT M_count_any       │
  ├────────────┼──────────────────────┼──────────────────────┤
  │        4   │ Θ(4) portes          │ 3 règles (constant)  │
  │      100   │ Θ(100) portes        │ 3 règles (constant)  │
  │   10 000   │ Θ(10 000) portes     │ 3 règles (constant)  │
  │ 1 000 000  │ Θ(1 M) portes        │ 3 règles (constant)  │
  └────────────┴──────────────────────┴──────────────────────┘

  FE pour circuits (Gorbunov-VW 2012) : une clé sk_{C_N} par taille N.
  FE pour MT (Ananth-V 2021)          : une seule clé sk_M pour tout N.
""")

    # ── Partie 5 : vérification cohérence circuit ↔ MT ───────────────────────
    print("--- Vérification : C_parity_4 et tm_parity cohérents sur dim=4 ---")
    C4p = build_parity_circuit(4)
    print(f"\n  {'Bits':>20s}  {'C_parity_4':>12s}  {'tm_parity':>10s}  Cohérent")
    print("  " + "-" * 55)
    for bits in [
        [True,  False, True,  True ],
        [False, False, False, False],
        [True,  True,  True,  True ],
        [False, True,  False, True ],
    ]:
        cr = int(circuit_eval(C4p, bits))
        mr = tm_parity(bits)
        ok = "✅" if cr == mr else "❌"
        disp = str([int(b) for b in bits])
        print(f"  {disp:>20s}  {cr:>12d}  {mr:>10d}  {ok}")
    print("\n  → Les deux modèles sont cohérents sur dim=4.")
    print("    La MT généralise le circuit à toute taille.")


if __name__ == "__main__":
    demo()
