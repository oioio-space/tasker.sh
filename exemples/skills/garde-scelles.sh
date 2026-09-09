#!/usr/bin/env bash
# Garde des scellés — hook PreToolUse de Crush.
#
# Crush appelle ce script avant chaque outil que crush.json lui confie (edit,
# write, multiedit, bash), avec sur l'entrée standard un JSON :
# { "tool_name", "tool_input", "cwd", … }. Sortir avec le code 2 BLOQUE
# l'appel, et ce qui est écrit sur stderr revient au modèle comme motif.
#
# Ce que ce script refuse : un appel dont le CHEMIN visé (file_path, path) ou
# la COMMANDE (bash) nomme un dossier protégé. Le contenu écrit n'est pas
# examiné : un rapport a le droit de citer le chemin d'une pièce. Un bash de
# lecture (« ls /mnt/scelles ») est refusé aussi — c'est voulu : la lecture
# passe par view, ls, grep, glob, qui ne sont pas soumis à cette garde.
#
# Ce qu'il ne remplace pas : le montage en lecture seule (mount -o bind,ro),
# qui est la seule garantie réelle. Ceci est une ceinture de plus, lisible,
# qui explique au modèle pourquoi il ne peut pas.
#
# Réglage : les dossiers protégés, un par ligne, dans
# ~/.config/crush/scelles.txt — à défaut, ou si la liste est vide, /mnt/scelles.

set -u
liste="${CRUSH_SCELLES:-$HOME/.config/crush/scelles.txt}"
proteges=()
if [[ -r "$liste" ]]; then
    mapfile -t proteges < <(grep -vE '^[[:space:]]*(#|$)' "$liste")
fi
(( ${#proteges[@]} )) || proteges=(/mnt/scelles)

# ce que l'appel vise : les champs de chemin et la commande, rien d'autre
cibles="$(python3 -c '
import json, sys
e = json.load(sys.stdin).get("tool_input") or {}
for k in ("file_path", "path", "command"):
    v = e.get(k)
    if isinstance(v, str):
        print(v)
' 2>/dev/null)"

for p in "${proteges[@]}"; do
    p="${p%/}"
    if grep -qF -- "$p" <<< "$cibles"; then
        echo "refusé : « $p » est un scellé, monté en lecture seule. Le skill ne" \
             "modifie jamais une pièce ; pour lire, servez-vous de view, grep ou ls ;" \
             "le rapport et ses fichiers de travail vont dans le dossier d'analyse." >&2
        exit 2
    fi
done
exit 0
