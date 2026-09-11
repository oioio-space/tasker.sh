#!/usr/bin/env bash
# La garde des scellés, sur les appels que Crush lui soumet vraiment :
# refuse-t-elle ce qu'il faut, et laisse-t-elle passer le travail du skill ?
#
#     tests/garde.sh [dossier de travail]
#
# Le point qui compte : un scellé se reconnaît à sa STRUCTURE, pas à son
# chemin. Un chemin écrit en dur ne protège rien sur un poste où la collecte
# est ailleurs — tout en ayant l'air de marcher, ce qui est le pire état
# possible pour une ceinture de sécurité. Ce test pose donc la collecte à un
# endroit quelconque, et vérifie qu'elle est quand même reconnue.
#
# L'autre point : la garde doit AUTORISER les scripts du skill sur le scellé.
# Sans cela elle refuse la toute première commande du skill, qui doit bien
# lire la collecte pour en tirer des faits.
set -u
ici="$(cd "$(dirname "$0")/.." && pwd)"
garde="$ici/garde-scelles.sh"
travail="${1:-$(mktemp -d)}"

# Un chemin que personne n'aurait deviné : c'est tout l'intérêt.
C="$travail/Documents/dossier-2026/analyse/PC01_S01_SYCOBS_LINUX"
mkdir -p "$C"/{SYSTEME,COMPTES,JOURNAUX,RESEAU,TIMELINE} "$travail/analyse"
# Un dossier ordinaire qui porte UN nom de la liste : il ne doit pas geler
# le poste de l'analyste.
mkdir -p "$travail/travail/RESEAU"

manques=0
essai() {                       # <libellé> <code attendu> <json>
    local code
    printf '%s' "$3" | bash "$garde" >/dev/null 2>&1
    code=$?
    if [[ "$code" == "$2" ]]; then
        printf "  ok      %s\n" "$1"
    else
        printf "  MANQUE  %s — code=%d, attendu %d\n" "$1" "$code" "$2"
        manques=$((manques + 1))
    fi
}

echo "── CE QUE LA GARDE DOIT LAISSER PASSER ──"
essai "extraire.py sur le scellé, sortie hors scellé" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 scripts/extraire.py $C/ -o $travail/analyse/faits.jsonl\"}}"
essai "controles.py sur le scellé" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 scripts/controles.py $C -o constats.jsonl\"}}"
essai "le rapport, écrit dans le dossier d'analyse" 0 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/analyse/rapport.md\"}}"
essai "un dossier ordinaire qui porte un seul RESEAU/" 0 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/travail/RESEAU/x\"}}"

echo "── CE QU'ELLE DOIT REFUSER ──"
essai "écrire dans une pièce du scellé" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$C/SYSTEME/hostname\"}}"
essai "poser un fichier NEUF au fond du scellé" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$C/JOURNAUX/sous/neuf.txt\"}}"
essai "effacer le scellé" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"rm -rf $C\"}}"
essai "un lecteur du skill, PUIS autre chose" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 extraire.py $C ; rm -rf $C\"}}"
essai "un lecteur du skill, redirigé DANS le scellé" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 extraire.py x > $C/SYSTEME/z\"}}"

# Sept contournements, tous mesurés comme PASSANT avant correction. Le
# premier a réellement écrasé une pièce du scellé pendant la revue : il
# suffisait d'écrire le nom d'un lecteur du skill dans un COMMENTAIRE.
echo "── LES CONTOURNEMENTS ──"
essai "le mot magique en commentaire" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"cp /etc/hosts $C/SYSTEME/hostname # extraire.py\"}}"
essai "un lecteur qui ÉCRIT dans le scellé (-o)" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 extraire.py $C -o $C/faits.jsonl\"}}"
essai "tar -x dont le nom porte « extraire.py »" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"tar -xzf extraire.py.tgz -C $C\"}}"
essai "une seconde commande après un saut de ligne" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 extraire.py $C\nrm -rf $C\"}}"
essai "un enchaînement par « & »" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 extraire.py $C & rm -rf $C\"}}"
# Un chemin RELATIF au dossier de travail : sans « cwd », ce n'était même pas
# vu comme un chemin, faute de barre oblique.
essai "un chemin relatif, depuis le dossier parent" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"rm -rf PC01_S01_SYCOBS_LINUX\"},\"cwd\":\"$(dirname "$C")\"}"
essai "un lecteur qui écrit HORS du scellé (doit passer)" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"python3 extraire.py $C -o $travail/analyse/f.jsonl\"}}"

# Le fichier de déclaration reste possible, pour protéger en plus un dossier
# qui n'est pas une collecte — un dossier d'affaire, par exemple.
echo "── LA LISTE DÉCLARÉE, EN PLUS DE LA STRUCTURE ──"
printf '%s\n' "$travail/affaire" > "$travail/scelles.txt"
mkdir -p "$travail/affaire"
CRUSH_SCELLES="$travail/scelles.txt" essai "un dossier déclaré à la main" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/affaire/note.txt\"}}"

echo
echo "$travail"
if (( manques )); then
    echo "$manques appel(s) mal traité(s) — voir ci-dessus." >&2
    exit 1
fi
exit 0
