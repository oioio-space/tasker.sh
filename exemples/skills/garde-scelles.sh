#!/usr/bin/env bash
# Garde des scellés — hook PreToolUse de Crush.
#
# Crush appelle ce script avant chaque outil que crush.json lui confie (edit,
# write, multiedit, bash), avec sur l'entrée standard un JSON :
# { "tool_name", "tool_input", "cwd", … }. Sortir avec le code 2 BLOQUE
# l'appel, et ce qui est écrit sur stderr revient au modèle comme motif.
#
# UN SCELLÉ SE RECONNAÎT À SA STRUCTURE, PAS À SON CHEMIN. C'est tout le
# principe de ce script. Un chemin écrit en dur — /mnt/scelles ou un autre —
# ne protège rien sur un poste où la collecte est ailleurs, tout en ayant
# l'air de marcher : c'est le pire état possible pour une ceinture de sécurité.
# Ici, un dossier qui porte au moins trois des dossiers que collecte-linux.conf
# écrit EST une collecte, où qu'il soit posé, et le reste sans qu'on ait rien
# à déclarer.
#
# Ce qui est refusé : écrire dans un scellé, ou y toucher par une commande
# quelconque. Ce qui est AUTORISÉ : lancer les scripts du skill dessus — ils
# ne modifient jamais leur entrée, c'est leur invariant et les tests le
# vérifient. Sans cette autorisation la garde refuserait la toute première
# commande du skill, qui doit bien lire la collecte pour en tirer des faits.
#
# Ce qu'il ne remplace pas : le montage en lecture seule (mount -o bind,ro),
# qui est la seule garantie réelle. Ceci est une ceinture de plus, lisible,
# qui explique au modèle pourquoi il ne peut pas.
#
# Réglage FACULTATIF : des dossiers à protéger en plus, un par ligne, dans
# ~/.config/crush/scelles.txt — ou $XDG_CONFIG_HOME/crush/scelles.txt si cette
# variable est posée, comme Crush lui-même. CRUSH_SCELLES nomme directement un
# autre fichier. Sans ce fichier, la reconnaissance par structure suffit.

set -u

# ÉCHOUER FERMÉ. Un hook qui sort autrement que 2 laisse passer l'appel : sans
# python3, la garde s'ouvrait en silence — elle avait l'air d'être là et ne
# refusait plus rien. Mieux vaut bloquer et le dire.
if ! command -v python3 >/dev/null 2>&1; then
    echo "refusé : python3 est introuvable, la garde des scellés ne peut pas" \
         "s'exécuter. Tant qu'elle ne peut pas juger, rien n'écrit." >&2
    exit 2
fi

export TK_SCELLES="${CRUSH_SCELLES:-${XDG_CONFIG_HOME:-$HOME/.config}/crush/scelles.txt}"

# Le programme est capturé dans une variable, et NON passé sur l'entrée
# standard : celle-ci porte le JSON de Crush, et un « python3 - » la mangerait.
garde=$(cat <<'PY'
import json, os, sys

# Les dossiers que collecte-linux.conf écrit sous PREFIX/.
DOSSIERS = {"SYSTEME", "PAQUETS", "COMPTES", "CONNEXIONS", "RESEAU",
            "PERSISTANCE", "JOURNAUX", "TIMELINE", "MACHINES", "SUPPRIMES",
            "PHOTOREC", "STRINGS"}
# Trois, et non un : un dossier qui s'appellerait « RESEAU » sans être une
# collecte ne doit pas geler le poste de l'analyste.
ASSEZ = 3

# Les scripts du skill ne modifient JAMAIS leur entrée : ils lisent les
# archives en flux, sans les dépaqueter, et écrivent ailleurs.
LECTEURS = ("extraire.py", "controles.py", "brouillon.py")
# … mais seulement s'ils sont SEULS. Un enchaînement ou une redirection peut
# remettre n'importe quoi derrière le lecteur.
ENCHAINE = (";", "&&", "||", "|", ">", "<", "`", "$(")


def est_collecte(d):
    try:
        return sum(1 for x in os.listdir(d)
                   if x in DOSSIERS and os.path.isdir(os.path.join(d, x))) >= ASSEZ
    except OSError:
        return False


def scelle_touche(chemin, declares):
    """Le scellé que ce chemin vise, ou None. On remonte les parents : écrire
    un fichier NEUF au fond d'une collecte doit être refusé comme le reste."""
    p = os.path.abspath(os.path.expanduser(chemin))
    for d in declares:
        if p == d or p.startswith(d + os.sep):
            return d
    while True:
        if est_collecte(p):
            return p
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


e = json.load(sys.stdin)
outil = str(e.get("tool_name") or "").lower()
entree = e.get("tool_input") or {}

declares = []
try:
    with open(os.environ.get("TK_SCELLES", ""), encoding="utf-8") as fh:
        declares = [os.path.abspath(os.path.expanduser(l.strip().rstrip("/")))
                    for l in fh if l.strip() and not l.lstrip().startswith("#")]
except OSError:
    pass

commande = entree.get("command") if isinstance(entree.get("command"), str) else ""
vises = [v for k in ("file_path", "path") for v in (entree.get(k),) if isinstance(v, str)]
# D'une commande, on ne retient que ce qui ressemble à un chemin.
vises += [t.strip("'\"") for t in commande.split() if "/" in t or t.startswith("~")]

touche = next((s for c in vises for s in (scelle_touche(c, declares),) if s), None)
if not touche:
    sys.exit(0)

if outil == "bash" and any(s in commande for s in LECTEURS) \
        and not any(d in commande for d in ENCHAINE):
    sys.exit(0)          # un lecteur du skill, seul : c'est son travail

print(f"refusé : « {touche} » est un scellé — une collecte, reconnue à sa "
      "structure. Le skill ne modifie jamais une pièce. Pour LIRE, servez-vous "
      "de view, grep, ls, ou lancez extraire.py / controles.py dessus (seuls, "
      "sans redirection ni enchaînement) ; le rapport et les fichiers de "
      "travail vont dans le dossier d'analyse, hors du scellé.", file=sys.stderr)
sys.exit(2)
PY
)
python3 -c "$garde"
