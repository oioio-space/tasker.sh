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

# L'IMAGE MONTÉE. Quand la collecte ne porte pas la pièce cherchée, l'analyse
# doit pouvoir aller la chercher sur l'image elle-même. Elle se reconnaît, comme
# le scellé, à sa STRUCTURE — une racine Linux porte etc/ et usr/ — et jamais à
# son chemin : « mnt/ » est une convention, pas une adresse.
M="$travail/analyse/mnt"
mkdir -p "$M"/{etc,usr,var,bin,home,root}
printf 'root:x:0:0::/root:/bin/sh\n' > "$M/etc/passwd"

echo "── L'IMAGE MONTÉE : TOUT CE QUI LIT ──"
essai "cat sur un fichier de l'image" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"cat $M/etc/passwd\"}}"
essai "strings, puis tri, vers le dossier d'analyse" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"strings $M/var/log/x | sort -u > $travail/analyse/s.txt\"}}"
essai "grep récursif, même sur le mot « rm »" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"grep -r 'rm -rf' $M/home\"}}"
essai "find et sqlite3 en lecture" 0 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"find $M/home -name places.sqlite\"}}"

echo "── L'IMAGE MONTÉE : RIEN DE CE QUI ÉCRIT ──"
essai "écrire un fichier dans l'image" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$M/etc/note.txt\"}}"
essai "rediriger DANS l'image" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"strings $M/var/log/x > $M/tmp/s.txt\"}}"
essai "effacer dans l'image" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"rm -rf $M/var/log\"}}"
essai "copier VERS l'image" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"cp /etc/hosts $M/etc/hosts\"}}"
essai "sed -i sur un fichier de l'image" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"sed -i s/a/b/ $M/etc/passwd\"}}"
# La redirection COLLÉE au mot qui précède : « cat a>b ». L'ancienne détection
# découpait à l'indice et exigeait un descripteur numérique devant le « > » ;
# « a » n'en étant pas un, elle passait.
essai "une redirection collée au mot" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"cat /etc/hosts>$M/etc/h\"}}"
essai "une lecture, PUIS une écriture" 2 \
  "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"cat $M/etc/passwd ; touch $M/etc/vu\"}}"
# Le poste de l'analyste n'est pas une image : « / » porte etc/ et usr/ lui
# aussi, et la garde refuserait alors absolument tout.
essai "la racine du poste n'est pas une image" 0 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/analyse/rapport2.md\"}}"

# Le fichier de déclaration reste possible, pour protéger en plus un dossier
# qui n'est pas une collecte — un dossier d'affaire, par exemple.
echo "── LA LISTE DÉCLARÉE, EN PLUS DE LA STRUCTURE ──"
printf '%s\n' "$travail/affaire" > "$travail/scelles.txt"
mkdir -p "$travail/affaire"
CRUSH_SCELLES="$travail/scelles.txt" essai "un dossier déclaré à la main" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/affaire/note.txt\"}}"

# DEUX listes qui s'additionnent : celle de l'affaire et celle du poste. Une
# seule était lue, et l'ajout d'un « :-./scelles.txt » dans le défaut aurait
# produit un chemin littéral « …/scelles.txt:-./scelles.txt » — lu par
# personne, et sans un mot. Vu poser la question ; d'où ces cas.
mkdir -p "$travail/nas" "$travail/poste_a_part" "$travail/affaire-tk"
printf '%s\n' "$travail/nas"          > "$travail/affaire-tk/scelles.txt"
printf '%s\n' "$travail/poste_a_part" > "$travail/conf-tk-crush.txt"

CRUSH_PROJECT_DIR="$travail/affaire-tk" \
  essai "la liste de l'AFFAIRE est lue" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/nas/x\"}}"
CRUSH_SCELLES="$travail/affaire-tk/scelles.txt:$travail/conf-tk-crush.txt" \
  essai "deux listes séparées par « : » s'additionnent (1/2)" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/nas/x\"}}"
CRUSH_SCELLES="$travail/affaire-tk/scelles.txt:$travail/conf-tk-crush.txt" \
  essai "deux listes séparées par « : » s'additionnent (2/2)" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/poste_a_part/x\"}}"
# Un fichier de liste absent n'est PAS une erreur : c'est le cas courant.
CRUSH_SCELLES="$travail/rien-du-tout.txt:$travail/non-plus.txt" \
  essai "des listes absentes ne cassent rien" 0 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$travail/analyse/r.md\"}}"

# ── « --essai » : la garde se contrôle elle-même ──────────────────────
# Le contrôle tapé à la main dans le README pouvait rendre 0 pour une faute
# de frappe — « scelles » pour « scelle », un cwd qui n'est pas le dossier
# d'analyse —, et ce 0 se lisait « la garde ne mord pas ». Vu en vrai. Le
# mode --essai sonde chaque sous-dossier avec le VRAI programme : il n'y a
# plus de chemin à taper, donc plus rien à mal taper.
echo "── LA GARDE SE CONTRÔLE ELLE-MÊME ──"
aff="$travail/affaire-essai"
mkdir -p "$aff"/{outils,scelle,mnt}

verdict() {                     # <libellé> <code attendu> <motif attendu>
    local sortie code
    sortie=$(bash "$garde" --essai "$aff" 2>&1); code=$?
    if [[ "$code" == "$2" ]] && grep -qF "$3" <<< "$sortie"; then
        printf "  ok      %s\n" "$1"
    else
        printf "  MANQUE  %s — code=%d (attendu %s), sortie :\n%s\n" \
               "$1" "$code" "$2" "$sortie"
        manques=$((manques + 1))
    fi
}

# Rien de monté : c'est le cas qu'un « code 0 » tapé à la main ne distinguait
# PAS d'une garde cassée. Ici il est nommé, et l'essai échoue.
verdict "rien de monté : l'essai le DIT" 1 "AUCUN SCELLÉ RECONNU"

# Un scellé, reconnu à sa structure sous un nom quelconque.
mkdir -p "$aff/scelle"/{SYSTEME,COMPTES,JOURNAUX}
verdict "un scellé monté : la garde mord" 0 "la garde mord."
verdict "et l'essai le nomme SCELLÉ" 0 "SCELLÉ"
verdict "sans image, il le dit sans échouer" 0 "aucune image montée"

# Une image : l'écriture refusée, la LECTURE libre — c'est tout l'intérêt.
mkdir -p "$aff/mnt"/{etc,usr,var,home,root,boot}
verdict "une image montée : lecture libre" 0 "lecture libre"

# Le dossier d'analyse lui-même doit rester écrivable : une garde qui refuse
# tout est aussi cassée qu'une garde qui ne refuse rien.
verdict "le rapport reste écrivable" 0 "le rapport peut y être écrit"

# Le mode --essai ne doit pas changer le comportement normal : sans argument,
# la garde lit toujours son JSON sur l'entrée standard.
essai "sans --essai, le JSON reste lu" 2 \
  "{\"tool_name\":\"write\",\"tool_input\":{\"file_path\":\"$aff/scelle/SYSTEME/x\"}}"

echo
echo "$travail"
if (( manques )); then
    echo "$manques appel(s) mal traité(s) — voir ci-dessus." >&2
    exit 1
fi
exit 0
