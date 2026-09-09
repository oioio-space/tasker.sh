#!/usr/bin/env bash
# Garde des scellés — hook PreToolUse de Crush.
#
# Crush appelle ce script avant chaque outil qui peut écrire (edit, write,
# bash…), avec sur l'entrée standard un JSON : { "tool_name", "tool_input",
# "cwd", … }. Sortir avec le code 2 BLOQUE l'appel, et ce qui est écrit sur
# stderr revient au modèle comme motif du refus.
#
# Ce que ce script refuse : tout ce qui nomme un chemin sous les scellés.
# Ce qu'il ne remplace pas : le montage en lecture seule
# (mount -o bind,ro), qui est la seule garantie réelle. Ceci est une ceinture
# de plus, lisible, qui explique au modèle pourquoi il ne peut pas.
#
# Réglage : la liste des dossiers protégés, un par ligne, dans
# ~/.config/crush/scelles.txt — à défaut, /mnt/scelles.

set -u
liste="${CRUSH_SCELLES:-$HOME/.config/crush/scelles.txt}"
if [[ -r "$liste" ]]; then
    mapfile -t proteges < <(grep -v '^\s*#' "$liste" | grep -v '^\s*$')
else
    proteges=(/mnt/scelles)
fi

entree="$(cat)"
for p in "${proteges[@]}"; do
    p="${p%/}"
    # le chemin apparaît-il, tel quel ou avec un tilde ou une variable, dans
    # l'appel ? On refuse large : un faux positif coûte une reformulation, un
    # faux négatif coûte une pièce.
    if grep -qF -- "$p" <<< "$entree"; then
        echo "refusé : « $p » est un scellé, monté en lecture seule. Le skill ne" \
             "modifie jamais une pièce ; le rapport et ses fichiers de travail" \
             "vont dans le dossier d'analyse." >&2
        exit 2
    fi
done
exit 0
