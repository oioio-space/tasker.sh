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
import json, os, re, sys

# Les dossiers que collecte-linux.conf écrit sous PREFIX/.
DOSSIERS = {"SYSTEME", "PAQUETS", "COMPTES", "CONNEXIONS", "RESEAU",
            "PERSISTANCE", "JOURNAUX", "TIMELINE", "MACHINES", "SUPPRIMES",
            "PHOTOREC", "STRINGS"}
# Trois, et non un : un dossier qui s'appellerait « RESEAU » sans être une
# collecte ne doit pas geler le poste de l'analyste.
ASSEZ = 3

# Les scripts du skill ne modifient JAMAIS leur entrée : ils lisent les
# archives en flux, sans les dépaqueter, et écrivent là où « -o » le dit.
#
# La commande doit COMMENCER par l'un d'eux. Chercher leur nom n'importe où
# dans la ligne ne valait rien : « cp /etc/hosts SCELLE/SYSTEME/hostname
# # extraire.py » passait, et détruisait la pièce. Le mot magique en
# commentaire suffisait à tout blanchir.
RE_LECTEUR = re.compile(r'\s*(?:[\w./-]*python[\d.]*\s+)?[\w./-]*'
                        r'(?:extraire|controles|brouillon)\.py(?=\s|$)')
# Tout ce qui peut remettre une commande derrière la première, ou rediriger.
# « & » et le saut de ligne manquaient ; « # » aussi, et c'était le trou.
ENCHAINE = (";", "&", "|", ">", "<", "`", "$(", "#", "\n", "\r", "\\")
# Où le lecteur ÉCRIT. Un « -o » qui vise le scellé n'est pas une redirection
# au sens du shell, donc rien ne l'arrêtait — alors que c'est la façon la plus
# naturelle d'y écrire par mégarde.
SORTIES = ("-o", "--sortie", "--out")


def est_collecte(d):
    try:
        return sum(1 for x in os.listdir(d)
                   if x in DOSSIERS and os.path.isdir(os.path.join(d, x))) >= ASSEZ
    except OSError:
        return False


def scelle_touche(chemin, declares, cwd=None):
    """Le scellé que ce chemin vise, ou None. On remonte les parents : écrire
    un fichier NEUF au fond d'une collecte doit être refusé comme le reste."""
    p = os.path.expanduser(chemin)
    p = os.path.abspath(os.path.join(cwd, p) if cwd and not os.path.isabs(p) else p)
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
# Le dossier de travail : sans lui, « rm -rf PC01_… » depuis le dossier parent
# n'était même pas vu comme un chemin.
cwd = e.get("cwd") if isinstance(e.get("cwd"), str) else None

declares = []
try:
    with open(os.environ.get("TK_SCELLES", ""), encoding="utf-8") as fh:
        declares = [os.path.abspath(os.path.expanduser(l.strip().rstrip("/")))
                    for l in fh if l.strip() and not l.lstrip().startswith("#")]
except OSError:
    pass

commande = entree.get("command") if isinstance(entree.get("command"), str) else ""
vises = [v for k in ("file_path", "path") for v in (entree.get(k),) if isinstance(v, str)]
# TOUT mot d'une commande est un chemin possible : un nom sans barre oblique
# en est un, relatif au dossier de travail.
mots = [t.strip("'\"") for t in commande.split()]
vises += [m for m in mots if m and not m.startswith("-")]

touche = next((s for c in vises for s in (scelle_touche(c, declares, cwd),) if s), None)
if not touche:
    sys.exit(0)

if outil == "bash" and RE_LECTEUR.match(commande) \
        and not any(d in commande for d in ENCHAINE) \
        and not any(scelle_touche(v, declares, cwd)
                    for o, v in zip(mots, mots[1:]) if o in SORTIES):
    sys.exit(0)          # un lecteur du skill, seul, qui écrit hors du scellé

print(f"refusé : « {touche} » est un scellé — une collecte, reconnue à sa "
      "structure. Le skill ne modifie jamais une pièce. Pour LIRE, servez-vous "
      "de view, grep, ls, ou lancez extraire.py / controles.py dessus (seuls, "
      "sans redirection ni enchaînement) ; le rapport et les fichiers de "
      "travail vont dans le dossier d'analyse, hors du scellé.", file=sys.stderr)
sys.exit(2)
PY
)
python3 -c "$garde"
