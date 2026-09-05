#!/usr/bin/env bash
#
# forensic.sh — enchaîne des commandes, validées une à une.
#     ./forensic.sh -h       aide          ./forensic.sh --demo   essai sans risque
#
#   1 VARIABLES · 2 COMMANDES · 3 LISTES · 4 CHEMINS · 5 FONCTIONS · 6 MÉCANIQUE
#   Tout ce qui se modifie est dans les cinq premières. Voir aussi TUTORIEL.md.
#
set -uo pipefail
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}" -lt 43 ]; then
    printf 'bash 4.3 ou plus est requis (trouvé : %s)\n' "${BASH_VERSION:-?}" >&2; exit 1
fi


# =====================================================================
# 1. VARIABLES     aussi : -c fichier.conf, ou --set NOM=valeur
# =====================================================================
IMAGE="/images/pc07.dd"        # image disque à analyser
PC="PC07"                      # poste
SALLE="B204"                   # salle
OS="windows"                   # windows ou linux
BASE="/cases"                  # racine où tout est écrit
OPERATEUR="${USER:-inconnu}"   # noté dans le journal et le rapport
TZ_MACTIME="Europe/Paris"      # fuseau du POSTE ANALYSÉ (un nom de zone, jamais UTC+1)
TOUT_VALIDER="false"           # true = confirmer chaque étape (ou -v)
MAX_ITERATIONS=500             # au-delà, une étape répétée est tronquée
REQUIS=(mmls fls ils icat mactime testdisk photorec)   # absents = avertissement


# =====================================================================
# 2. COMMANDES     "Titre|validation|commande"
#
#   validation  true = demander avant de lancer, false = lancer direct ;
#               puis, séparées par des virgules : log (sortie au journal),
#               continu (un échec n'arrête rien), stop (un échec arrête tout)
#   $VAR        remplacée maintenant ; \$ pour qu'elle survive jusqu'à
#               l'exécution :  for f in *; do echo \$f; done
#   [[nom]]     une valeur demandée une fois, réutilisée partout
#   {{nom}}     l'étape est rejouée pour chaque valeur de la liste « nom »,
#               toujours entre apostrophes : '{{nom}}'
#   Pas de | dans le titre ; ceux de la commande sont libres.
#   Le tout est dans une fonction pour que $IMAGE etc. suivent -c et --set.
# =====================================================================
definir_commandes() {

COMMANDES=(
"Table des partitions|true,log|mmls '$IMAGE'"
"Fichiers alloués et supprimés|true|fls -r -p -m / -o [[offset]] '$IMAGE' > '$DIR_BODY/${PREFIX}_fls.body'"
"Inodes non alloués|true,continu|ils -m -o [[offset]] '$IMAGE' > '$DIR_BODY/${PREFIX}_ils.body'"
"Fusion des body files|false|fusionner_body '$DIR_BODY/${PREFIX}_full.body' '$DIR_BODY/${PREFIX}_fls.body' '$DIR_BODY/${PREFIX}_ils.body'"
"Timeline|true|mactime -b '$DIR_BODY/${PREFIX}_full.body' -z '$TZ_MACTIME' -d -y > '$DIR_TIMELINE/${PREFIX}_timeline.csv'"
"Inventaire par utilisateur|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' '{{home_libelle}}' '$DIR_BODY'"
"Liste des partitions (testdisk)|true,log|testdisk /list '$IMAGE'"
"Carving|true|photorec /log /logname '$DIR_LOGS/${PREFIX}_photorec.log' /d '$DIR_CARVING/recup_' /cmd '$IMAGE' [[index_testdisk]],fileopt,everything,enable,freespace,search"

# Un fichier de chaque profil : {{fichier}} dépend de {{home}}, la boucle
# sur les profils se déclenche toute seule. Vérifiez le nombre d'itérations.
#"Hachage fichier par fichier|true|hacher_fichier '$IMAGE' '[[offset]]' '{{fichier}}' '{{fichier_libelle}}' >> '$DIR_LOGS/${PREFIX}_hashes.txt'"

# Le .bashrc de chaque utilisateur (voir la liste « bashrc », section 3).
#"Contenu de chaque .bashrc|true,log|echo '--- {{bashrc_libelle}}'; icat -o [[offset]] '$IMAGE' '{{bashrc}}'"
)


# =====================================================================
# 3. LISTES        "nom|commande qui écrit une valeur par ligne"
#
#   [[nom]] dans une commande -> menu numéroté, une valeur choisie
#   {{nom}} dans une commande -> l'étape est rejouée pour chaque valeur
#
#   Une ligne  valeur<TAB>libellé  envoie la valeur dans la commande et
#   affiche le libellé, disponible en {{nom_libelle}}.
#
#   UNE LISTE PEUT EN APPELER UNE AUTRE, et c'est tout le mécanisme :
#   « fichier » contient {{home}}, donc elle est régénérée pour chaque
#   home — écrire {{fichier}} seul parcourt les fichiers de tous les
#   profils. Une liste qui ne renvoie rien ne produit aucune itération,
#   ce n'est pas une erreur. Exemple déroulé : TUTORIEL.md, § 7.
# =====================================================================
LISTES=(
"offset|lister_partitions '$IMAGE'"
"index_testdisk|lister_partitions_testdisk '$IMAGE'"
"home|lister_homes '$IMAGE' '[[offset]]' '$OS'"
"fichier|lister_fichiers '$IMAGE' '[[offset]]' '{{home}}'"

# Un fichier précis dans chaque home. Le motif est une expression
# régulière : ^\.bashrc$ pour ce seul nom, \.(bash|zsh)rc$ pour les deux.
#"bashrc|lister_fichiers_nommes '$IMAGE' '[[offset]]' '{{home}}' '^\.bashrc$'"
)

}


# =====================================================================
# 4. CHEMINS ET CONTRÔLES     ce que la mécanique attend de vous
# =====================================================================

# Recalculé après -c et --set. Quatre noms sont attendus, le reste vous
# appartient :
#   SUJET    titre court, en tête et au récapitulatif
#   DETAILS  lignes du bandeau de départ, "clé=valeur" (clé sans accent)
#   PREFIX   préfixe des fichiers écrits
#   DIR_xxx  dossiers de travail, vérifiés et créés au besoin.
#            DIR_LOGS reçoit le journal, le rapport et l'état de reprise.
calculer_variables() {
    SUJET="$PC · $SALLE · $OS"
    DETAILS=("image=$IMAGE" "fuseau=$TZ_MACTIME")

    PREFIX="${PC}_${SALLE}_${OS}"
    DEST="$BASE/$SALLE/$OS/$PC"
    DIR_BODY="$DEST/body"
    DIR_TIMELINE="$DEST/timeline"
    DIR_CARVING="$DEST/carving"
    DIR_LOGS="$DEST/logs"
}

# Contrôles avant de commencer : renvoyez 1 pour arrêter. Les dossiers et
# les binaires de REQUIS sont déjà vérifiés par ailleurs.
verifier() {
    [[ -e "$IMAGE" ]] || { erreur "image absente : $IMAGE"
        info "réglez IMAGE en section 1, ou : --set IMAGE=/chemin.dd · -c poste.conf · --demo pour essayer sans image"
        return 1; }
    [[ -r "$IMAGE" ]] || { erreur "image illisible : $IMAGE"; return 1; }
    [[ -d /usr/share/zoneinfo && ! -e "/usr/share/zoneinfo/$TZ_MACTIME" ]] && attention "fuseau inconnu du système : $TZ_MACTIME"
    return 0
}

# =====================================================================
# 5. FONCTIONS
#    Une fonction d'étape termine par return (son code fait ● ou ✗).
#    Une fonction de liste écrit une valeur par ligne, ses erreurs sur >&2.
#    Dans une boucle longue :  (( INTERROMPU )) && return 130
# =====================================================================

# Menu de [[offset]] : offset<TAB>type et taille.
lister_partitions() {
    mmls "$1" 2>/dev/null | awk '
        /Units are in/ { for (i=1; i<=NF; i++) if ($i ~ /-byte/) { split($i, u, "-"); unite = u[1] } }
        $1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9]+:[0-9]+$/ {
            desc = $6; for (i = 7; i <= NF; i++) desc = desc " " $i
            if (desc ~ /^Unallocated/) next
            if (unite == "") unite = 512
            o = $5 * unite
            if      (o >= 1073741824) t = sprintf("%.1f Go", o / 1073741824)
            else if (o >= 1048576)    t = sprintf("%.1f Mo", o / 1048576)
            else                      t = sprintf("%d o", o)
            printf "%d\t%s — %s\n", $3 + 0, desc, t
        }'
    return "${PIPESTATUS[0]}"
}

# Menu de [[index_testdisk]] : le numéro que photorec attend.
lister_partitions_testdisk() {
    testdisk /list "$1" 2>/dev/null | awk '
        $1 ~ /^[0-9]+$/ && $2 ~ /^[PLED*]$/ {
            d = $3; for (i = 4; i <= NF; i++) d = d " " $i
            printf "%d\t%s\n", $1, d
        }'
    return "${PIPESTATUS[0]}"
}

# lister_homes <image> <offset> <os> : inode<TAB>chemin de chaque profil.
lister_homes() {
    local img="$1" off="$2" racine ino
    case "${3,,}" in windows|win) racine="Users" ;; *) racine="home" ;; esac

    ino=$(fls -o "$off" -D -p "$img" 2>/dev/null | awk -F'\t' -v r="$racine" '
        { n = $2; sub(/^.*\//, "", n)
          if (tolower(n) == tolower(r)) { split($1, c, " "); i = c[length(c)]; sub(/:$/, "", i); print i; exit } }')
    [[ -n "$ino" ]] || { printf 'pas de dossier "%s" sur la partition %s\n' "$racine" "$off" >&2; return 1; }

    # Profils système écartés ; retirez la ligne tolower(...) pour les garder.
    fls -o "$off" -D -p "$img" "$ino" 2>/dev/null | awk -F'\t' '
        { n = $2; sub(/^.*\//, "", n)
          if (n == "." || n == ".." || n ~ /^\$/) next
          if (tolower(n) ~ /^(all users|default|default user|public)$/) next
          split($1, c, " "); i = c[length(c)]; sub(/:$/, "", i)
          printf "%s\t%s%s\n", i, $2, ($1 ~ /\*/) ? " (supprimé)" : "" }'
    return 0
}

# lister_fichiers <image> <offset> <inode> : inode<TAB>chemin, récursif.
lister_fichiers() {
    fls -o "$2" -F -p -r "$1" "$3" 2>/dev/null | awk -F'\t' '
        { split($1, c, " "); i = c[length(c)]; sub(/:$/, "", i)
          if (i !~ /^[0-9]/) next
          printf "%s\t%s%s\n", i, $2, ($1 ~ /\*/) ? " (supprimé)" : "" }'
    return 0
}

# lister_fichiers_nommes <image> <offset> <inode> <motif>
# Les fichiers d'un dossier dont le NOM correspond au motif — le reste du
# chemin est ignoré. Une liste vide n'est pas une erreur : un home sans
# .bashrc produit simplement zéro itération.
lister_fichiers_nommes() {
    lister_fichiers "$1" "$2" "$3" | awk -F'\t' -v m="$4" '
        { n = $2; sub(/^.*\//, "", n); if (n ~ m) print }'
    return 0
}

# fusionner_body <sortie> <entrées...> : ignore les fichiers absents ou vides.
fusionner_body() {
    local sortie="$1" f n; shift
    local -a ok=()
    for f in "$@"; do
        [[ -s "$f" ]] && ok+=("$f") || printf '  (ignoré : %s)\n' "$f"
    done
    (( ${#ok[@]} )) || { printf 'rien à fusionner\n' >&2; return 1; }
    cat "${ok[@]}" > "$sortie" || return 1
    n=$(wc -l < "$sortie" | tr -d ' ')
    printf '  %s ligne%s -> %s\n' "$n" "$(pluriel "$n")" "$sortie"
    return 0
}

# inventorier_home <image> <offset> <inode> <chemin> <dossier> : un body par profil.
inventorier_home() {
    local sortie n
    sortie="$5/home_$(nettoyer_nom "$4").body"
    fls -r -p -m "/$4" -o "$2" "$1" "$3" > "$sortie" || return 1
    n=$(wc -l < "$sortie" | tr -d ' ')
    printf '  %s entrée%s -> %s\n' "$n" "$(pluriel "$n")" "$sortie"
    return 0
}

# hacher_fichier <image> <offset> <inode> <chemin>
hacher_fichier() {
    local h
    h=$(icat -o "$2" "$1" "$3" 2>/dev/null | sha256sum | cut -d' ' -f1) || return 1
    printf '%s  %s\n' "$h" "$4"
    return 0
}

# nettoyer_nom <texte> : un nom de fichier sûr.
nettoyer_nom() {
    local s="${1//\//_}"; s="${s// /_}"; s="${s//[^A-Za-z0-9._-]/}"
    printf '%s' "${s:-sans_nom}"
}


# =====================================================================
# 6. MÉCANIQUE
# =====================================================================

# --- 5.1 Affichage ---------------------------------------------------
COULEUR="auto"
LARGEUR=80
NOM_SCRIPT="${0##*/}"

init_affichage() {
    local actif="non"
    case "$COULEUR" in
        oui)  actif="oui" ;;
        auto) [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]] && actif="oui" ;;
    esac
    if [[ "$actif" == "oui" ]]; then
        C0=$'\033[0m'; GRAS=$'\033[1m'; ESTOMPE=$'\033[2m'
        ROUGE=$'\033[31m'; VERT=$'\033[32m'; JAUNE=$'\033[33m'
        BLEU=$'\033[34m'; MAGENTA=$'\033[35m'; CYAN=$'\033[36m'
    else
        C0=""; GRAS=""; ESTOMPE=""; ROUGE=""; VERT=""; JAUNE=""; BLEU=""; MAGENTA=""; CYAN=""
    fi
    # Palette : une couleur par rôle, jamais de fond (lisible sur thème clair et sombre).
    C_PROG="$GRAS$CYAN"      # le programme lancé
    C_CMD="$GRAS"            # ses arguments
    C_OK="$VERT"; C_KO="$GRAS$ROUGE"; C_WARN="$JAUNE"; C_SIM="$BLEU"
    C_BOUCLE="$MAGENTA"      # étiquettes d'itération  agent=alice
    C_CLE="$GRAS"            # touches des menus
    C_BOITE="$BLEU"          # cadre des questions
    [[ -t 1 ]] && LARGEUR=$(tput cols 2>/dev/null || printf 80)
    [[ "$LARGEUR" =~ ^[0-9]+$ ]] || LARGEUR=80
    (( LARGEUR < 40 )) && LARGEUR=40
    (( LARGEUR > 100 )) && LARGEUR=100
}

# Sous une locale POSIX, ${#x} compte les octets : « é » en vaut deux et
# les colonnes se décalent. On mesure la largeur réelle.
_SONDE="é"; UTF8_OK=0; (( ${#_SONDE} == 1 )) && UTF8_OK=1; unset _SONDE
largeur_texte() {
    if (( UTF8_OK )); then printf '%s' "${#1}"
    else local t="${1//[$'\x80'-$'\xbf']/}"; printf '%s' "${#t}"; fi
}
pad_droite() {   # <texte> <largeur>
    local n=$(( $2 - $(largeur_texte "$1") ))
    (( n < 0 )) && n=0
    printf '%s%s' "$1" "$(repeter ' ' "$n")"
}
repeter() { local i s=""; for (( i = 0; i < $2; i++ )); do s+="$1"; done; printf '%s' "$s"; }
regle()   { printf '%s%s%s\n' "${1:-$ESTOMPE}" "$(repeter '─' "$LARGEUR")" "$C0"; }
pluriel() { (( $1 > 1 )) && printf 's'; return 0; }
entete()  { printf '  %s%-10s%s %s\n' "$ESTOMPE" "$1" "$C0" "$2"; }   # clé ASCII
info()      { printf '  %s%s%s\n'     "$ESTOMPE" "$*" "$C0"; }
attention() { printf '  %s⚠  %s%s\n'  "$JAUNE"   "$*" "$C0"; }
erreur()    { printf '%s✗  %s%s\n'    "$ROUGE"   "$*" "$C0" >&2; }

barre() {   # <fait> <total>
    local larg=12 plein
    plein=$(( $1 * larg / ($2 > 0 ? $2 : 1) ))
    (( plein > larg )) && plein=$larg
    printf '%s%s%s%s%s' "$VERT" "$(repeter '━' "$plein")" "$ESTOMPE" "$(repeter '━' $(( larg - plein )))" "$C0"
}

duree() {   # <secondes>
    if   (( $1 < 60 ));   then printf '%ds' "$1"
    elif (( $1 < 3600 )); then printf '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 ))
    else                       printf '%dh%02dm' $(( $1 / 3600 )) $(( $1 % 3600 / 60 )); fi
}

# ○ à faire  ◐ en cours  ● réussie  ✗ échec  ⊘ passée  ⊗ interrompue  ◌ simulée
# Une colonne chacun, jamais d'emoji : ils en prennent deux et cassent l'alignement.
glyphe() {
    case "$1" in
        todo)  printf '%s○%s' "$ESTOMPE" "$C0" ;;  cours) printf '%s◐%s' "$CYAN"  "$C0" ;;
        ok)    printf '%s●%s' "$C_OK"    "$C0" ;;  ko)    printf '%s✗%s' "$C_KO"  "$C0" ;;
        skip)  printf '%s⊘%s' "$ESTOMPE" "$C0" ;;  int)   printf '%s⊗%s' "$JAUNE" "$C0" ;;
        sim)   printf '%s◌%s' "$BLEU"    "$C0" ;;  *)     printf ' ' ;;
    esac
}
glyphe_texte() {
    case "$1" in
        todo) printf 'a faire' ;; cours) printf 'en cours' ;; ok) printf 'ok' ;; ko) printf 'ECHEC' ;;
        skip) printf 'passee' ;;  int) printf 'interrompue' ;; sim) printf 'simulee' ;; *) printf '?' ;;
    esac
}

colonne_titre() { local l=$(( LARGEUR - 22 )); (( l < 24 )) && l=24; (( l > 52 )) && l=52; printf '%s' "$l"; }

ligne_tache() {   # <état> <numéro> <titre> <détail>
    local ct=""
    case "$1" in ko) ct="$C_KO" ;; int) ct="$C_WARN" ;; skip) ct="$ESTOMPE" ;; sim) ct="$C_SIM" ;; esac
    if [[ -z "$4" ]]; then
        printf '  %s %s%2s%s  %s%s%s\n' "$(glyphe "$1")" "$ESTOMPE" "$2" "$C0" "$ct" "$3" "$C0"
    else
        printf '  %s %s%2s%s  %s%s%s  %s%s%s\n' "$(glyphe "$1")" "$ESTOMPE" "$2" "$C0" \
               "$ct" "$(pad_droite "$3" "$(colonne_titre)")" "$C0" "$ESTOMPE" "$4" "$C0"
    fi
}

titre_etape() {   # <numéro> <total> <titre>
    printf '\n'; regle
    printf '  %s %s%s%d/%d%s  %s  %s%s%s\n' "$(glyphe cours)" "$GRAS" "$CYAN" "$1" "$2" "$C0" \
           "$(barre "$(( $1 - 1 ))" "$2")" "$GRAS" "$3" "$C0"
    regle
}

# Repliée aux espaces si elle dépasse l'écran : c'est la ligne à relire.
afficher_commande() {   # <commande> [indentation]
    local cmd="$1" ind="${2:-  }" dispo premiere=1 ligne prog reste
    dispo=$(( LARGEUR - ${#ind} - 2 )); (( dispo < 24 )) && dispo=24
    while IFS= read -r ligne; do
        if (( premiere )); then
            prog="${ligne%% *}"; reste="${ligne#"$prog"}"
            printf '%s%s$%s %s%s%s%s%s%s\n' "$ind" "$ESTOMPE" "$C0" "$C_PROG" "$prog" "$C0" "$C_CMD" "$reste" "$C0"
            premiere=0
        else
            printf '%s    %s%s%s\n' "$ind" "$C_CMD" "$ligne" "$C0"
        fi
    done < <(printf '%s\n' "$cmd" | fold -s -w "$dispo")
}

menu() {   # clé=texte ... — la première clé est celle de la touche Entrée
    local e ligne=""
    [[ "$SANS_QUESTION" == "true" ]] && return 0
    for e in "$@"; do
        ligne+="${ligne:+$ESTOMPE · $C0}${C_CLE}${e%%=*}${C0} ${ESTOMPE}${e#*=}${C0}"
    done
    printf '  %s\n' "$ligne"
}
invite() { printf '  %s›%s ' "$GRAS" "$C0"; }


# --- 5.2 Aide --------------------------------------------------------
aide() {
    cat <<'FIN_AIDE'
forensic.sh — enchaîne des commandes, validées une à une.

  ./forensic.sh                  lance les étapes
  ./forensic.sh --demo           essai dans un bac à sable, sans image disque
  ./forensic.sh -c poste.conf    variables lues dans un fichier
  ./forensic.sh --etapes         montre le plan sans rien lancer
  ./forensic.sh -n               simulation : tout est affiché, rien n'est exécuté

À chaque étape      Entrée exécuter · p passer · e éditer · r ressaisir · q quitter
Étape répétée       u une par une · l lister les itérations
Question posée      1 2 3 choisir · a autre valeur · p passer · q quitter
Ctrl-C              pendant une commande : l'interrompt, le script continue
                    pendant une question : arrête le script proprement

Dans le script      1. variables    ce qui change d'une exécution à l'autre
                    2. commandes    "Titre|true|commande"   true = demander avant
                    3. listes       "nom|commande"          une valeur par ligne
                    4. chemins      où écrire, quoi vérifier au départ
                    5. fonctions    vos traitements
    [[nom]]   une valeur demandée une fois, réutilisée dans toutes les étapes.
              S'il existe une liste du même nom, la question devient un menu.
    {{nom}}   l'étape est rejouée pour chaque valeur de la liste « nom ».
              Une liste peut en utiliser une autre : les boucles s'emboîtent.
              Ainsi la liste « bashrc » cherche .bashrc dans {{home}} :
              écrire '{{bashrc}}' seul parcourt le .bashrc de chaque
              utilisateur, et saute ceux qui n'en ont pas.

Options             -v tout confirmer         -y ne rien demander
                    --seulement 2,5-7         --depuis 4        --reprendre
                    --var nom=valeur          --liste nom=a,b   --vars
                    --set NOM=valeur  (toute variable de la section 1)
                    --sans-couleur            --couleur oui|non|auto

Marques             ○ à faire  ◐ en cours  ● réussie  ✗ échec
                    ⊘ passée   ⊗ interrompue  ◌ simulée

Sorties             <base>/<salle>/<os>/<pc>/logs/  journal, rapport, état (--reprendre)
Code de sortie      0 si tout est passé, 1 s'il reste un échec.
FIN_AIDE
}


# --- 5.3 Arguments et configuration ----------------------------------
PRESETS=(); PRESETS_LISTE=(); SETS=()
CONF=""; INTRO=""
LISTER_VARS="false"; LISTER_ETAPES="false"; SIMULATION="false"
SANS_QUESTION="false"; REPRENDRE="false"; FILTRE_ETAPES=""; DEPUIS=0

exige_valeur() { [[ -n "${2:-}" ]] || { printf '%s attend une valeur.\n' "$1" >&2; exit 1; }; }

while (( $# > 0 )); do
    case "$1" in
        -v|--valider)   TOUT_VALIDER="true";  shift ;;
        -y|--oui)       SANS_QUESTION="true"; shift ;;
        -n|--simulation|--dry-run) SIMULATION="true"; shift ;;
        --etapes|--plan) LISTER_ETAPES="true"; shift ;;
        --vars)         LISTER_VARS="true";   shift ;;
        --reprendre)    REPRENDRE="true";     shift ;;
        --demo)         CONF="$(dirname "${BASH_SOURCE[0]}")/exemples/demo.conf"; shift ;;
        --sans-couleur) COULEUR="non";        shift ;;
        --var)          exige_valeur "$1" "${2:-}"; PRESETS+=("$2");       shift 2 ;;
        --var=*)        PRESETS+=("${1#*=}");                              shift ;;
        --liste)        exige_valeur "$1" "${2:-}"; PRESETS_LISTE+=("$2"); shift 2 ;;
        --liste=*)      PRESETS_LISTE+=("${1#*=}");                        shift ;;
        --seulement)    exige_valeur "$1" "${2:-}"; FILTRE_ETAPES="$2";    shift 2 ;;
        --seulement=*)  FILTRE_ETAPES="${1#*=}";                           shift ;;
        --depuis)       exige_valeur "$1" "${2:-}"; DEPUIS="$2";           shift 2 ;;
        --depuis=*)     DEPUIS="${1#*=}";                                  shift ;;
        -c|--conf)      exige_valeur "$1" "${2:-}"; CONF="$2";             shift 2 ;;
        --conf=*)       CONF="${1#*=}";                                    shift ;;
        --couleur)      exige_valeur "$1" "${2:-}"; COULEUR="$2";          shift 2 ;;
        --couleur=*)    COULEUR="${1#*=}";                                 shift ;;
        --set)          exige_valeur "$1" "${2:-}"; SETS+=("$2");           shift 2 ;;
        --set=*)        SETS+=("${1#*=}");                                 shift ;;
        -h|--help|--aide) aide; exit 0 ;;
        *) printf 'Argument inconnu : %s   (-h pour aide)\n' "$1" >&2; exit 1 ;;
    esac
done
case "$COULEUR" in oui|non|auto) ;; *) printf -- '--couleur attend oui, non ou auto.\n' >&2; exit 1 ;; esac
init_affichage

# Le fichier -c est du shell : il peut fixer les variables, mais aussi
# redéfinir definir_commandes et ajouter des fonctions (voir exemples/demo.conf).
if [[ -n "$CONF" ]]; then
    [[ -r "$CONF" ]] || { erreur "configuration illisible : $CONF"; exit 1; }
    bash -n "$CONF" 2>/dev/null || { erreur "erreur de syntaxe dans $CONF"; bash -n "$CONF"; exit 1; }
    # shellcheck disable=SC1090
    source "$CONF" || { erreur "échec du chargement de $CONF"; exit 1; }
fi
# --set NOM=valeur : n'importe quelle variable de la section 1. On exige
# qu'elle existe déjà, sinon une faute de frappe passerait inaperçue.
for e in ${SETS[@]+"${SETS[@]}"}; do
    k="${e%%=*}"
    [[ "$e" == *=* && "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { erreur "--set attend NOM=valeur : $e"; exit 1; }
    declare -p "$k" >/dev/null 2>&1 || { erreur "--set : aucune variable « $k » en section 1"; exit 1; }
    printf -v "$k" '%s' "${e#*=}" 2>/dev/null \
        || { erreur "--set : « $k » ne peut pas être modifiée (lecture seule ?)"; exit 1; }
done
case "${TOUT_VALIDER,,}" in true|oui|1) TOUT_VALIDER="true" ;; *) TOUT_VALIDER="false" ;; esac
[[ "$MAX_ITERATIONS" =~ ^[0-9]+$ ]] && (( MAX_ITERATIONS >= 1 )) \
    || { erreur "MAX_ITERATIONS doit être un entier positif : $MAX_ITERATIONS"; exit 1; }
[[ "$DEPUIS" =~ ^[0-9]+$ ]] || { erreur "--depuis attend un numéro d'étape"; exit 1; }
if [[ -n "$FILTRE_ETAPES" ]]; then
    IFS=, read -r -a _morceaux <<< "$FILTRE_ETAPES"
    for m in "${_morceaux[@]}"; do
        [[ "$m" =~ ^[0-9]+(-[0-9]+)?$ ]] || { erreur "--seulement : « $m » n'est ni un numéro ni un intervalle"; exit 1; }
    done
fi

calculer_variables
# Sans ces trois-là, la mécanique casserait bien plus loin, sur une
# variable non définie, à un endroit qui n'aiderait personne. Le cas se
# produit dès qu'un fichier -c redéfinit calculer_variables.
for v in SUJET PREFIX DIR_LOGS; do
    [[ -n "${!v:-}" ]] || { erreur "calculer_variables doit définir $v (section 4, ou votre fichier -c)"; exit 1; }
done
[[ "$PREFIX" != */* ]] || { erreur "PREFIX ne peut pas contenir de / : $PREFIX"; exit 1; }

definir_commandes
TOTAL=${#COMMANDES[@]}


# --- 5.4 Saisies et signaux ------------------------------------------
# Les questions se lisent sur /dev/tty : l'entrée standard peut être
# prise par une commande.
if (exec 3< /dev/tty) 2>/dev/null; then ENTREE="/dev/tty"; INTERACTIF="oui"
else ENTREE="/dev/stdin"; INTERACTIF="non"; fi

LOG="/dev/null"
journal() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }

# Ctrl-C pendant une commande : on interrompt la commande, INTERROMPU=1.
# Ctrl-C pendant une question : arrêt propre. Ce second cas est
# indispensable : bash n'interrompt pas un « read » sur un signal piégé,
# il exécute le gestionnaire puis retourne attendre — le script
# paraîtrait figé.
INTERROMPU=0; EN_SAISIE=0
gerer_int() {
    if (( EN_SAISIE )); then
        EN_SAISIE=0; printf '\n'; attention "interruption au clavier — arrêt."
        journal "ARRÊT : Ctrl-C pendant une question"; exit 130
    fi
    INTERROMPU=1
}
trap gerer_int INT

# lire <invite> <variable> : Entrée vide = défaut ; Ctrl-D = arrêt.
lire() {
    local rc
    [[ "$SANS_QUESTION" == "true" ]] && { printf -v "$2" '%s' ""; return 0; }
    EN_SAISIE=1
    # shellcheck disable=SC2229
    read -r -p "$1" "$2" < "$ENTREE"; rc=$?
    EN_SAISIE=0
    if (( rc != 0 )); then
        printf '\n'; erreur "fin de l'entrée clavier (Ctrl-D) — arrêt."
        journal "ARRÊT : fin de l'entrée clavier"; exit 130
    fi
    return 0
}
lire_edit() {   # <valeur initiale> <variable>
    EN_SAISIE=1
    read -r -e -i "$1" -p "  ${CYAN}\$${C0} " "$2" < "$ENTREE" || true
    EN_SAISIE=0
}
demander_oui_non() {   # vrai sauf n / q
    local r=""; lire "$1" r
    case "${r,,}" in n|non|q) return 1 ;; *) return 0 ;; esac
}
quitter() { printf '\n'; info "arrêt demandé."; journal "ARRÊT demandé"; exit "${1:-0}"; }


# --- 5.5 Valeurs, listes, emboîtement --------------------------------
RE_SIMPLE='\[\[([a-zA-Z0-9_]+)\]\]'
RE_LISTE='\{\{([a-zA-Z0-9_]+)\}\}'

# =() est obligatoire : sous set -u, un « declare -A X » nu rend ${#X[@]} illégal.
declare -A REPONSES=()      # [[nom]] -> valeur
declare -A GENERATEUR=()    # liste   -> commande
declare -A CACHE_LISTE=()   # commande résolue -> lignes
declare -A LISTE_FIGEE=()   # --liste nom=a,b
declare -A BINDINGS=()      # {{nom}} liés dans la boucle en cours (échappés)
PH_SIMPLES=(); USAGE_SIMPLES=(); PH_LISTES=(); USAGE_LISTES=()
ETAPE_PASSEE=0              # mis à 1 quand l'utilisateur répond « p » à une question

echapper_apostrophes() { printf '%s' "${1//\'/\'\\\'\'}"; }

charger_listes() {
    local e nom
    for e in ${LISTES[@]+"${LISTES[@]}"}; do
        nom="${e%%|*}"
        [[ "$e" == *"|"* && -n "${e#*|}" ]] || { erreur "LISTES : il faut nom|commande : $e"; exit 1; }
        [[ "$nom" =~ ^[a-zA-Z0-9_]+$ && "$nom" != *_libelle ]] || { erreur "LISTES : nom invalide « $nom »"; exit 1; }
        [[ -z "${GENERATEUR[$nom]:-}" ]] || { erreur "LISTES : « $nom » défini deux fois"; exit 1; }
        GENERATEUR["$nom"]="${e#*|}"
    done
}

substituer_liaisons() {   # remplace les {{nom}} déjà liés
    local t="$1" k
    if (( ${#BINDINGS[@]} > 0 )); then
        for k in "${!BINDINGS[@]}"; do t="${t//\{\{$k\}\}/${BINDINGS[$k]}}"; done
    fi
    printf '%s' "$t"
}

liste_de() {   # {{home_libelle}} désigne la liste « home »
    local n="$1"
    [[ -z "${GENERATEUR[$n]:-}${LISTE_FIGEE[$n]:-}" && "$n" == *_libelle ]] && n="${n%_libelle}"
    printf '%s' "$n"
}

valeur_valide() {
    [[ -n "$1" ]] || { printf '    %svaleur vide refusée%s\n' "$JAUNE" "$C0"; return 1; }
    [[ "$1" != *'[['* && "$1" != *'{{'* ]] || { printf '    %s[[ et {{ sont interdits dans une valeur%s\n' "$JAUNE" "$C0"; return 1; }
    return 0
}

etapes_mot() { if [[ "$1" == *,* ]]; then printf 'aux étapes'; else printf "à l'étape"; fi; }
ou_sert() {   # <nom> : « 2, 3 et par la liste home »
    local i
    for i in ${PH_SIMPLES[@]+"${!PH_SIMPLES[@]}"}; do
        [[ "${PH_SIMPLES[$i]}" == "$1" ]] && { printf '%s' "${USAGE_SIMPLES[$i]}"; return 0; }
    done
    return 0
}

# generer_liste <nom> -> VALEURS, LIBELLES. Recopiez-les aussitôt : un
# appel imbriqué (une liste qui en appelle une autre) les écrase.
# Renvoie 0 (des valeurs), 2 (aucune valeur) ou 1 (erreur). Vide et erreur
# sont distincts : un home sans .bashrc ne doit pas annuler toute l'étape,
# il doit seulement ne produire aucune itération.
VALEURS=(); LIBELLES=()
generer_liste() {
    local nom="$1" gen sortie rc ligne val lib

    if [[ -n "${LISTE_FIGEE[$nom]:-}" ]]; then
        VALEURS=(); LIBELLES=()
        while IFS= read -r ligne; do [[ -n "$ligne" ]] && { VALEURS+=("$ligne"); LIBELLES+=(""); }; done <<< "${LISTE_FIGEE[$nom]}"
        return 0
    fi
    [[ -n "${GENERATEUR[$nom]:-}" ]] || {
        erreur "aucune liste « $nom » en section 3 (voir --vars)"
        info "si {{$nom}} n'était pas censé être une liste, doublez l'accolade autrement"
        return 1; }

    resoudre_simples "${GENERATEUR[$nom]}" || return 1
    gen="$(substituer_liaisons "$CMD")"
    if [[ "$gen" =~ $RE_LISTE ]]; then
        erreur "la liste « $nom » dépend de {{${BASH_REMATCH[1]}}} : elle ne peut pas servir ici"; return 1
    fi

    if [[ -n "${CACHE_LISTE[$gen]:-}" ]]; then
        sortie="${CACHE_LISTE[$gen]}"; [[ "$sortie" == $'\001' ]] && sortie=""
    else
        journal "LISTE $nom : $gen"
        [[ -t 1 ]] && printf '  %s… lecture de la liste « %s »%s' "$ESTOMPE" "$nom" "$C0"
        sortie="$(eval "$gen" 2>> "$LOG")"; rc=$?
        [[ -t 1 ]] && printf '\r%s\r' "$(repeter ' ' $(( ${#nom} + 30 )))"
        if (( rc != 0 && ${#sortie} == 0 )); then erreur "la liste « $nom » a échoué (code $rc) — voir $LOG"; return 1; fi
        CACHE_LISTE["$gen"]="${sortie:-$'\001'}"
    fi

    # Remise à zéro ICI : la résolution ci-dessus a pu rappeler generer_liste.
    VALEURS=(); LIBELLES=()
    while IFS= read -r ligne; do
        [[ -n "$ligne" ]] || continue
        val="${ligne%%$'\t'*}"; lib=""; [[ "$ligne" == *$'\t'* ]] && lib="${ligne#*$'\t'}"
        if [[ "$val" == *'[['* || "$val" == *'{{'* ]]; then attention "valeur ignorée dans « $nom » : $val"; continue; fi
        VALEURS+=("$val"); LIBELLES+=("$lib")
    done <<< "$sortie"
    (( ${#VALEURS[@]} > 0 )) || { journal "LISTE $nom : aucune valeur"; return 2; }
    return 0
}

# demander_valeur <nom> -> VALEUR ; 1 si l'utilisateur passe l'étape.
VALEUR=""
demander_valeur() {
    local nom="$1" i n choix ou libre=0
    local -a v=() l=()

    if [[ -n "${GENERATEUR[$nom]:-}${LISTE_FIGEE[$nom]:-}" ]]; then
        generer_liste "$nom"
        case $? in
            0) v=("${VALEURS[@]}"); l=("${LIBELLES[@]}") ;;
            2) attention "la liste « $nom » n'a rien renvoyé — saisissez la valeur" ;;
        esac
    fi
    INTERROMPU=0
    ou="$(ou_sert "$nom")"; n=${#v[@]}

    printf '\n    %s┌─%s %s[[%s]]%s%s%s\n' "$C_BOITE" "$C0" "$C_PROG" "$nom" "$C0" "$ESTOMPE" "${ou:+  — utilisé $(etapes_mot "$ou") $ou}"
    if (( n > 0 )); then
        printf '    %s│%s\n' "$C_BOITE" "$C0"
        for i in "${!v[@]}"; do
            printf '    %s│%s  %s%2d%s  %s%s%s' "$C_BOITE" "$C0" "$C_CLE" $(( i + 1 )) "$C0" "$GRAS$C_OK" "${v[$i]}" "$C0"
            [[ -n "${l[$i]}" ]] && printf '%s  %s%s' "$(pad_droite '' $(( 14 - $(largeur_texte "${v[$i]}") )))" "$ESTOMPE${l[$i]}" "$C0"
            printf '\n'
        done
        printf '    %s│%s\n' "$C_BOITE" "$C0"
        if [[ "$SANS_QUESTION" != "true" ]]; then
            printf '    %s│%s  %s a%s  %ssaisir une autre valeur%s\n' "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
            printf '    %s│%s  %s p%s  %spasser cette étape%s\n'       "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
            printf '    %s│%s  %s q%s  %squitter le script%s\n'        "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
        fi
        while true; do
            choix=""; lire "    $BLEU└─$C0 votre choix ${ESTOMPE}[1]${C0} ${GRAS}›${C0} " choix
            [[ -z "$choix" ]] && choix=1
            case "${choix,,}" in
                a) libre=1; break ;;
                p) ETAPE_PASSEE=1; printf '    %sétape passée%s\n' "$ESTOMPE" "$C0"; return 1 ;;
                q) quitter 0 ;;
            esac
            if [[ "$choix" =~ ^[0-9]+$ ]] && (( choix >= 1 && choix <= n )); then
                # Valeur produite par un programme : on neutralise les apostrophes.
                VALEUR="$(echapper_apostrophes "${v[$(( choix - 1 ))]}")"
                printf '    %s→ %s%s\n\n' "$C_OK" "${v[$(( choix - 1 ))]}" "$C0"; return 0
            fi
            printf '    %s« %s » n'"'"'est pas dans la liste%s\n' "$JAUNE" "$choix" "$C0"
        done
    else
        printf '    %s│%s  %sla valeur sera réutilisée partout où [[%s]] apparaît%s\n' "$C_BOITE" "$C0" "$ESTOMPE" "$nom" "$C0"
        printf '    %s│%s  %s p%s  %spasser cette étape%s   %s q%s  %squitter%s\n' "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
    fi

    if [[ "$SANS_QUESTION" == "true" ]]; then
        erreur "[[$nom]] n'a pas de valeur et -y interdit de la demander : --var $nom=…"; exit 1
    fi
    # Après « a », p et q sont des valeurs comme les autres.
    VALEUR=""
    while true; do
        lire "    $BLEU└─$C0 valeur ${GRAS}›${C0} " VALEUR
        if (( ! libre )); then
            case "${VALEUR,,}" in
                p) ETAPE_PASSEE=1; printf '    %sétape passée%s\n' "$ESTOMPE" "$C0"; return 1 ;;
                q) quitter 0 ;;
            esac
        fi
        valeur_valide "$VALEUR" && break
    done
    printf '\n'; return 0
}

# resoudre_simples <commande> -> CMD ; 1 si l'utilisateur passe l'étape.
# Résultat dans une variable et non $(...) : un sous-shell perdrait REPONSES.
CMD=""
resoudre_simples() {
    local cmd="$1" nom
    while [[ "$cmd" =~ $RE_SIMPLE ]]; do
        nom="${BASH_REMATCH[1]}"
        if [[ -z "${REPONSES[$nom]:-}" ]]; then
            demander_valeur "$nom" || return 1
            REPONSES["$nom"]="$VALEUR"
        fi
        cmd="${cmd//\[\[$nom\]\]/${REPONSES[$nom]}}"
    done
    CMD="$cmd"
}

# oublier_valeurs <commande brute> : les [[valeurs]] de cette étape, y
# compris celles des listes qu'elle appelle, et le cache des listes.
oublier_valeurs() {
    local i=0 courant nom vus=" "
    local -a afaire=("$1")
    while (( i < ${#afaire[@]} )); do
        courant="${afaire[$i]}"; i=$(( i + 1 ))
        while [[ "$courant" =~ $RE_SIMPLE ]]; do
            unset "REPONSES[${BASH_REMATCH[1]}]"; courant="${courant//\[\[${BASH_REMATCH[1]}\]\]/}"
        done
        while [[ "$courant" =~ $RE_LISTE ]]; do
            nom="${BASH_REMATCH[1]}"; courant="${courant//\{\{$nom\}\}/}"; nom="$(liste_de "$nom")"
            [[ "$vus" == *" $nom "* || -z "${GENERATEUR[$nom]:-}" ]] || { vus+="$nom "; afaire+=("${GENERATEUR[$nom]}"); }
        done
    done
    CACHE_LISTE=()
}

# liste_a_parcourir <nom> : la liste sans dépendance non liée, en
# remontant la chaîne ({{fichier}} seul fait boucler sur {{home}}).
liste_a_parcourir() {
    local nom vus=" " gen
    nom="$(liste_de "$1")"
    while true; do
        [[ "$vus" != *" $nom "* ]] || { erreur "dépendance circulaire entre listes : $nom"; return 1; }
        vus+="$nom "
        gen="$(substituer_liaisons "${GENERATEUR[$nom]:-}")"
        [[ "$gen" =~ $RE_LISTE ]] || break
        nom="$(liste_de "${BASH_REMATCH[1]}")"
    done
    printf '%s' "$nom"
}

# expanser <commande> -> EXP_CMDS (une par combinaison), EXP_LABELS.
EXP_CMDS=(); EXP_LABELS=(); EXP_TRONQUE=0
expanser() { EXP_CMDS=(); EXP_LABELS=(); EXP_TRONQUE=0; BINDINGS=(); _expanser "$1" "" 0; }
_expanser() {
    local cmd label="$2" prof="$3" cible i val lib rc
    local -a v=() l=()
    (( prof > 6 )) && { erreur "plus de 6 listes emboîtées"; return 1; }
    (( INTERROMPU )) && return 130
    (( EXP_TRONQUE )) && return 0

    cmd="$(substituer_liaisons "$1")"
    if [[ ! "$cmd" =~ $RE_LISTE ]]; then
        (( ${#EXP_CMDS[@]} >= MAX_ITERATIONS )) && { EXP_TRONQUE=1; return 0; }
        EXP_CMDS+=("$cmd"); EXP_LABELS+=("$label"); return 0
    fi
    cible="$(liste_a_parcourir "${BASH_REMATCH[1]}")" || return 1
    [[ -n "${GENERATEUR[$cible]:-}${LISTE_FIGEE[$cible]:-}" ]] || {
        erreur "aucune liste « $cible » en section 3 (voir --vars)"; return 1; }
    generer_liste "$cible"; rc=$?
    if (( rc == 2 )); then
        # Branche sans valeur : zéro itération ici, et c'est tout. Au
        # premier niveau on le dit, sinon l'étape entière paraîtrait muette.
        (( prof == 0 )) && attention "la liste « $cible » n'a renvoyé aucune valeur"
        return 0
    fi
    (( rc != 0 )) && return 1
    v=("${VALEURS[@]}"); l=("${LIBELLES[@]}")

    for i in "${!v[@]}"; do
        (( INTERROMPU )) && return 130
        (( EXP_TRONQUE )) && return 0
        val="${v[$i]}"; lib="${l[$i]:-$val}"
        BINDINGS["$cible"]="$(echapper_apostrophes "$val")"
        BINDINGS["${cible}_libelle"]="$(echapper_apostrophes "$lib")"
        _expanser "$cmd" "${label:+$label · }$cible=$lib" $(( prof + 1 )); rc=$?
        unset "BINDINGS[$cible]" "BINDINGS[${cible}_libelle]"
        (( rc != 0 )) && return "$rc"
    done
    return 0
}

# scanner_placeholders : inventaire pour --vars et le contrôle de --var,
# en suivant les listes appelées indirectement.
scanner_placeholders() {
    local i=0 k=0 e cmd nom gen
    _noter() {   # <tableau noms> <tableau usages> <nom> <où>
        local -n noms="$1"; local -n usages="$2"; local j t=-1
        for j in "${!noms[@]}"; do [[ "${noms[$j]}" == "$3" ]] && t=$j; done
        if (( t < 0 )); then noms+=("$3"); usages+=("$4")
        elif [[ "${usages[$t]}" != *"$4"* ]]; then
            if [[ "$4" == et\ * ]]; then usages[$t]+=" $4"; else usages[$t]+=", $4"; fi; fi
    }
    for e in "${COMMANDES[@]}"; do
        i=$(( i + 1 )); cmd="${e#*|}"; cmd="${cmd#*|}"
        while [[ "$cmd" =~ $RE_SIMPLE ]]; do nom="${BASH_REMATCH[1]}"; _noter PH_SIMPLES USAGE_SIMPLES "$nom" "$i"; cmd="${cmd//\[\[$nom\]\]/}"; done
        while [[ "$cmd" =~ $RE_LISTE ]];  do nom="${BASH_REMATCH[1]}"; cmd="${cmd//\{\{$nom\}\}/}"; _noter PH_LISTES USAGE_LISTES "$(liste_de "$nom")" "$i"; done
    done
    while (( k < ${#PH_LISTES[@]} )); do
        nom="${PH_LISTES[$k]}"; gen="${GENERATEUR[$nom]:-}"; k=$(( k + 1 ))
        while [[ "$gen" =~ $RE_SIMPLE ]]; do e="${BASH_REMATCH[1]}"; gen="${gen//\[\[$e\]\]/}"; _noter PH_SIMPLES USAGE_SIMPLES "$e" "et par la liste $nom"; done
        while [[ "$gen" =~ $RE_LISTE ]];  do e="${BASH_REMATCH[1]}"; gen="${gen//\{\{$e\}\}/}"; _noter PH_LISTES USAGE_LISTES "$(liste_de "$e")" "et par la liste $nom"; done
    done
    unset -f _noter
}


# --- 5.6 Exécution ---------------------------------------------------
analyser_validation() {   # "true,log" -> F_VALIDER F_LOG F_STOP F_CONTINU ; 1 si invalide
    local o; F_VALIDER=""; F_LOG=0; F_STOP=0; F_CONTINU=0; MSG_VALIDATION=""
    IFS=, read -r -a _opts <<< "${1,,}"
    for o in "${_opts[@]}"; do
        o="${o//[[:space:]]/}"
        case "$o" in
            true|vrai|oui|1) F_VALIDER="true" ;;  false|faux|non|0) F_VALIDER="false" ;;
            log) F_LOG=1 ;;  stop) F_STOP=1 ;;  continu|continue) F_CONTINU=1 ;;  "") ;;
            *) MSG_VALIDATION="option inconnue « $o »"; return 1 ;;
        esac
    done
    [[ -n "$F_VALIDER" ]] || { MSG_VALIDATION="il manque true ou false"; return 1; }
    (( F_STOP && F_CONTINU )) && { MSG_VALIDATION="stop et continu s'excluent"; return 1; }
    return 0
}

# executer_une <commande> <log 0/1> : code de la commande ; DUREE_S posé.
DUREE_S=0
executer_une() {
    local debut=$SECONDS rc
    INTERROMPU=0; journal "$1"
    [[ "$SIMULATION" == "true" ]] && { DUREE_S=0; return 0; }
    if (( $2 )); then
        # Un tube et non une substitution de processus : le shell attend tee,
        # et PIPESTATUS donne le vrai code. La commande perd son terminal :
        # d'où l'option explicite.
        eval "$1" 2>&1 | tee -a "$LOG"; rc=${PIPESTATUS[0]}
    else
        eval "$1"; rc=$?
    fi
    DUREE_S=$(( SECONDS - debut )); journal "code $rc en $(duree "$DUREE_S")"
    return "$rc"
}

# executer_groupe <une par une 0/1> <répétée 0/1> : joue EXP_CMDS.
# Résultat dans G_OK G_KO G_SKIP G_INT G_ARRET(1 boucle, 2 script) G_RC G_DUREE, ITERS.
G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_DUREE=0; G_RC=0; ITERS=()
executer_groupe() {
    local une_par_une="$1" repetee="$2" n=${#EXP_CMDS[@]} i rc choix ignorer=0 debut=$SECONDS
    G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_RC=0; ITERS=()

    for i in "${!EXP_CMDS[@]}"; do
        if (( repetee )); then
            printf '\n  %s──%s %s%d/%d%s %s──%s %s%s%s\n' "$ESTOMPE" "$C0" "$GRAS" $(( i + 1 )) "$n" "$C0" \
                   "$ESTOMPE" "$C0" "$C_BOUCLE" "${EXP_LABELS[$i]}" "$C0"
            afficher_commande "${EXP_CMDS[$i]}" "     "
        fi
        if (( une_par_une )); then
            menu "Entrée=exécuter" "p=passer" "t=tout enchaîner" "q=arrêter la boucle"
            choix=""; lire "$(invite)" choix
            case "${choix,,}" in
                p) printf '     %s⊘  passée%s\n' "$ESTOMPE" "$C0"; G_SKIP=$(( G_SKIP + 1 )); ITERS+=("skip|passee|${EXP_LABELS[$i]}"); continue ;;
                q) printf '     %sboucle arrêtée%s\n' "$JAUNE" "$C0"; G_ARRET=1; break ;;
                t) une_par_une=0 ;;
            esac
        fi

        executer_une "${EXP_CMDS[$i]}" "$F_LOG"; rc=$?

        if (( INTERROMPU )); then
            INTERROMPU=0
            printf '  %s⊗  interrompu%s %sau bout de %s%s\n' "$C_WARN" "$C0" "$ESTOMPE" "$(duree "$DUREE_S")" "$C0"
            G_INT=$(( G_INT + 1 )); ITERS+=("int|$(duree "$DUREE_S")|${EXP_LABELS[$i]}")
            (( repetee )) || break
            demander_oui_non "  Continuer la boucle ? ${ESTOMPE}[O/n]${C0} " && continue
            G_ARRET=1; break
        fi
        if (( rc == 0 )); then
            if [[ "$SIMULATION" == "true" ]]; then
                printf '  %s◌  simulée%s\n' "$C_SIM" "$C0"; ITERS+=("sim|simulee|${EXP_LABELS[$i]}")
            else
                printf '  %s●  terminée%s %sen %s%s\n' "$C_OK" "$C0" "$ESTOMPE" "$(duree "$DUREE_S")" "$C0"; ITERS+=("ok|$(duree "$DUREE_S")|${EXP_LABELS[$i]}")
            fi
            G_OK=$(( G_OK + 1 )); continue
        fi

        printf '  %s✗  échec%s %s— code %d, %s%s\n' "$C_KO" "$C0" "$ESTOMPE" "$rc" "$(duree "$DUREE_S")" "$C0"
        G_KO=$(( G_KO + 1 )); G_RC=$rc; ITERS+=("ko|code $rc|${EXP_LABELS[$i]}")
        (( F_CONTINU )) && { info "(étape marquée « continu » : on poursuit)"; continue; }
        (( F_STOP ))    && { erreur "étape marquée « stop » : arrêt du script."; G_ARRET=2; break; }
        (( ignorer ))   && continue
        if (( repetee )); then
            menu "Entrée=continuer" "t=continuer sans redemander" "n=arrêter la boucle" "q=quitter"
            choix=""; lire "$(invite)" choix
            case "${choix,,}" in t) ignorer=1 ;; n) G_ARRET=1; break ;; q) G_ARRET=2; break ;; esac
        else
            demander_oui_non "  Continuer quand même ? ${ESTOMPE}[O/n]${C0} " || G_ARRET=2
        fi
    done
    G_DUREE=$(( SECONDS - debut ))
    return 0
}

resume_iterations() {
    local n=${#EXP_CMDS[@]} i max=6
    printf '  %s↻  étape répétée%s — %s%d itération%s%s\n' "$C_BOUCLE" "$C0" "$GRAS" "$n" "$(pluriel "$n")" "$C0"
    for (( i = 0; i < n && i < max; i++ )); do printf '     %s%2d%s  %s%s%s\n' "$ESTOMPE" $(( i + 1 )) "$C0" "$C_BOUCLE" "${EXP_LABELS[$i]}" "$C0"; done
    (( n > max )) && printf '     %s..  et %d autre%s — « l » pour tout voir%s\n' "$ESTOMPE" $(( n - max )) "$(pluriel "$(( n - max ))")" "$C0"
    (( EXP_TRONQUE )) && attention "limite de $MAX_ITERATIONS itérations atteinte, liste tronquée (MAX_ITERATIONS, section 1)"
    return 0
}
lister_iterations() {
    local i; printf '\n'
    for i in "${!EXP_CMDS[@]}"; do
        printf '     %s%3d%s  %s%s%s\n' "$GRAS" $(( i + 1 )) "$C0" "$C_BOUCLE" "${EXP_LABELS[$i]}" "$C0"
        afficher_commande "${EXP_CMDS[$i]}" "          "
    done
    printf '\n'
}


# --- 5.7 Plan, récapitulatif, rapport --------------------------------
RECAP=()                # "num|état|détail|titre"
declare -A ENFANTS=()   # num -> itérations "état|détail|étiquette", séparées par \x01
NB_OK=0; NB_KO=0; NB_PASSEES=0
DEBUT_HORODATE="$(date '+%F %T %z')"

plan_initial() {   # [oui] = avec les commandes
    local i=0 e reste m
    printf '\n'; regle "$GRAS"
    printf ' %sPlan%s   %s%d étape%s%s\n' "$GRAS" "$C0" "$ESTOMPE" "$TOTAL" "$(pluriel "$TOTAL")" "$C0"
    regle "$GRAS"
    for e in "${COMMANDES[@]}"; do
        i=$(( i + 1 )); reste="${e#*|}"; analyser_validation "${reste%%|*}"
        m=""   # seul l'inhabituel est signalé : « auto » plutôt que « confirmation »
        [[ "${reste#*|}" == *"{{"* ]] && m+="${m:+ · }↻ répétée"
        [[ "$F_VALIDER" == "false" && "$TOUT_VALIDER" != "true" ]] && m+="${m:+ · }auto"
        (( F_LOG ))     && m+="${m:+ · }log"
        (( F_STOP ))    && m+="${m:+ · }stop"
        (( F_CONTINU )) && m+="${m:+ · }continu"
        if etape_retenue "$i"; then ligne_tache todo "$i" "${e%%|*}" "$m"
        else ligne_tache skip "$i" "${e%%|*}" "hors filtre"; fi
        [[ "${1:-}" == "oui" ]] && afficher_commande "${reste#*|}" "        "
    done
    [[ "${1:-}" == "oui" ]] && regle
    return 0
}

recap() {
    (( ${#RECAP[@]} == 0 )) && return
    local l num e d t
    printf '\n'; regle "$GRAS"
    printf ' %sRécapitulatif%s   %s%s%s\n' "$GRAS" "$C0" "$ESTOMPE" "$SUJET" "$C0"
    regle "$GRAS"
    for l in "${RECAP[@]}"; do
        num="${l%%|*}"; l="${l#*|}"; e="${l%%|*}"; l="${l#*|}"; d="${l%%|*}"; t="${l#*|}"
        ligne_tache "$e" "$num" "$t" "$d"
        recap_enfants "$num"
    done
    regle
    printf '  %s%d réussie%s%s · %s%d en échec%s · %s%d passée%s%s · total %s\n' \
           "$C_OK" "$NB_OK" "$(pluriel "$NB_OK")" "$C0" "$( (( NB_KO )) && printf '%s' "$C_KO" )" "$NB_KO" "$C0" \
           "$ESTOMPE" "$NB_PASSEES" "$(pluriel "$NB_PASSEES")" "$C0" "$(duree "$SECONDS")"
    printf '  %sjournal  %s%s\n' "$ESTOMPE" "$LOG" "$C0"
    ecrire_rapport
}
trap recap EXIT

# Au-delà de dix itérations, seules celles qui ont mal tourné sont montrées.
recap_enfants() {
    local brut="${ENFANTS[$1]:-}" i n e d t caches=0 tout=0
    local -a lignes=() montrees=()
    [[ -n "$brut" ]] || return 0
    mapfile -t lignes < <(printf '%s' "${brut//$'\x01'/$'\n'}")
    (( ${#lignes[@]} <= 10 )) && tout=1
    for i in "${!lignes[@]}"; do
        [[ -n "${lignes[$i]}" ]] || continue
        if (( ! tout )) && [[ "${lignes[$i]%%|*}" == "ok" ]]; then caches=$(( caches + 1 )); else montrees+=("${lignes[$i]}"); fi
    done
    n=${#montrees[@]}
    for i in "${!montrees[@]}"; do
        e="${montrees[$i]%%|*}"; d="${montrees[$i]#*|}"; t="${d#*|}"; d="${d%%|*}"
        printf '      %s%s%s %s %s  %s%s%s\n' "$ESTOMPE" "$( (( i == n - 1 && caches == 0 )) && printf '└─' || printf '├─')" "$C0" \
               "$(glyphe "$e")" "$(pad_droite "$t" $(( $(colonne_titre) - 3 )))" "$ESTOMPE" "$d" "$C0"
    done
    (( caches > 0 )) && printf '      %s└─ … et %d itération%s réussie%s%s\n' "$ESTOMPE" "$caches" "$(pluriel "$caches")" "$(pluriel "$caches")" "$C0"
    return 0
}

ecrire_rapport() {
    [[ -d "${DIR_LOGS:-}" ]] || return 0
    local f="$DIR_LOGS/${PREFIX}_rapport.txt" l num e d t ligne
    {
        printf 'Rapport %s\n  sujet      %s\n' "$NOM_SCRIPT" "$SUJET"
        for l in ${DETAILS[@]+"${DETAILS[@]}"}; do printf '  %-10s %s\n' "${l%%=*}" "${l#*=}"; done
        printf '  par         %s sur %s\n' "$OPERATEUR" "$(hostname 2>/dev/null || printf '?')"
        printf '  debut      %s\n  fin        %s\n  duree      %s\n\n' "$DEBUT_HORODATE" "$(date '+%F %T %z')" "$(duree "$SECONDS")"
        for l in "${RECAP[@]}"; do
            num="${l%%|*}"; l="${l#*|}"; e="${l%%|*}"; l="${l#*|}"; d="${l%%|*}"; t="${l#*|}"
            printf '  %2s  %-12s %-10s %s\n' "$num" "$(glyphe_texte "$e")" "$d" "$t"
            while IFS= read -r ligne; do
                [[ -n "$ligne" ]] || continue
                e="${ligne%%|*}"; d="${ligne#*|}"; t="${d#*|}"; d="${d%%|*}"
                printf '        %-12s %-10s %s\n' "$(glyphe_texte "$e")" "$d" "$t"
            done <<< "${ENFANTS[$num]:-}"
        done
        printf '\n  %d reussies, %d en echec, %d passees\n' "$NB_OK" "$NB_KO" "$NB_PASSEES"
    } > "$f" 2>/dev/null && printf '  %srapport  %s%s\n' "$ESTOMPE" "$f" "$C0"
}


# --- 5.8 Contrôles de départ -----------------------------------------
(( TOTAL > 0 )) || { erreur "le tableau COMMANDES est vide."; exit 1; }
for e in "${COMMANDES[@]}"; do
    reste="${e#*|}"
    [[ "$e" == *"|"* && "$reste" == *"|"* ]] || { erreur "format attendu Titre|validation|commande :"; printf '  %s\n' "$e" >&2; exit 1; }
    # Une commande réduite à des espaces passerait eval sans rien faire et
    # serait comptée réussie : c'est le pire des cas, on l'attrape ici.
    cmd_nue="${reste#*|}"; cmd_nue="${cmd_nue//[[:space:]]/}"
    [[ -n "$cmd_nue" ]] || { erreur "commande vide :"; printf '  %s\n' "$e" >&2; exit 1; }
    [[ -n "${e%%|*}" ]] || { erreur "titre vide :"; printf '  %s\n' "$e" >&2; exit 1; }
    analyser_validation "${reste%%|*}" || { erreur "validation « ${reste%%|*} » : $MSG_VALIDATION"; printf '  %s\n' "$e" >&2; exit 1; }
done
charger_listes
scanner_placeholders

etape_retenue() {   # <n> : passe --seulement et --depuis ?
    local m
    (( DEPUIS > 0 && $1 < DEPUIS )) && return 1
    [[ -n "$FILTRE_ETAPES" ]] || return 0
    for m in "${_morceaux[@]}"; do
        if [[ "$m" == *-* ]]; then (( $1 >= ${m%-*} && $1 <= ${m#*-} )) && return 0
        else (( $1 == m )) && return 0; fi
    done
    return 1
}

if [[ "$LISTER_VARS" == "true" ]]; then
    printf '\n'
    (( ${#PH_SIMPLES[@]} + ${#PH_LISTES[@]} > 0 )) || info "aucune valeur à fournir."
    for i in ${PH_SIMPLES[@]+"${!PH_SIMPLES[@]}"}; do
        printf '  %s[[%s]]%s  %s%s · %s %s%s\n' "$CYAN" "${PH_SIMPLES[$i]}" "$C0" "$ESTOMPE" \
               "$( [[ -n "${GENERATEUR[${PH_SIMPLES[$i]}]:-}" ]] && printf menu || printf saisie)" "$(etapes_mot "${USAGE_SIMPLES[$i]}")" "${USAGE_SIMPLES[$i]}" "$C0"
    done
    for i in ${PH_LISTES[@]+"${!PH_LISTES[@]}"}; do
        printf '  %s{{%s}}%s  %s%s %s%s\n         %s\n' "$MAGENTA" "${PH_LISTES[$i]}" "$C0" "$ESTOMPE" "$(etapes_mot "${USAGE_LISTES[$i]}")" "${USAGE_LISTES[$i]}" "$C0" "${GENERATEUR[${PH_LISTES[$i]}]:-(figée)}"
    done
    printf '\n  %s--var nom=valeur fournit une [[valeur]], --liste nom=a,b fige une {{liste}}%s\n\n' "$ESTOMPE" "$C0"
    exit 0
fi

connu_dans() { local x n="$1"; shift; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }
for p in ${PRESETS[@]+"${PRESETS[@]}"}; do
    nom="${p%%=*}"; val="${p#*=}"
    [[ "$p" == *=* && "$nom" =~ ^[a-zA-Z0-9_]+$ ]] || { erreur "--var attend nom=valeur : $p"; exit 1; }
    valeur_valide "$val" || exit 1
    connu_dans "$nom" ${PH_SIMPLES[@]+"${PH_SIMPLES[@]}"} || { erreur "aucun [[$nom]] dans les commandes (voir --vars)"; exit 1; }
    REPONSES["$nom"]="$val"
done
for p in ${PRESETS_LISTE[@]+"${PRESETS_LISTE[@]}"}; do
    nom="${p%%=*}"; val="${p#*=}"
    [[ "$p" == *=* && "$nom" =~ ^[a-zA-Z0-9_]+$ && -n "$val" ]] || { erreur "--liste attend nom=v1,v2 : $p"; exit 1; }
    connu_dans "$nom" ${PH_LISTES[@]+"${PH_LISTES[@]}"} || { erreur "aucune liste « $nom » utilisée (voir --vars)"; exit 1; }
    LISTE_FIGEE["$nom"]="${val//,/$'\n'}"
done

if [[ "$LISTER_ETAPES" == "true" ]]; then plan_initial oui; printf '\n'; exit 0; fi

verifier || exit 1
[[ "$INTERACTIF" == "non" && "$SANS_QUESTION" != "true" ]] && attention "aucun terminal : les réponses seront lues sur l'entrée standard (-y pour ne rien demander)"
MANQUANTS=""; for b in "${REQUIS[@]}"; do command -v "$b" >/dev/null 2>&1 || MANQUANTS+=" $b"; done
[[ -n "$MANQUANTS" ]] && attention "binaires absents :$MANQUANTS"

CREES=0
for nom in ${!DIR_@}; do
    d="${!nom}"
    [[ -n "$d" ]] || { erreur "$nom est vide."; exit 1; }
    if [[ ! -d "$d" && "$SIMULATION" != "true" ]]; then
        mkdir -p "$d" || { erreur "création impossible : $d"; exit 1; }; CREES=$(( CREES + 1 ))
    fi
    [[ "$SIMULATION" == "true" || -w "$d" ]] || attention "dossier non inscriptible : $d"
done
[[ "$SIMULATION" == "true" ]] || { LOG="$DIR_LOGS/${PREFIX}_script.log"; : >> "$LOG" || { erreur "journal non inscriptible : $LOG"; exit 1; }; }

# Reprise : empreinte du titre ET de la commande, une par étape réussie.
ETAT="$DIR_LOGS/${PREFIX}_etat.txt"
empreinte() {
    if command -v sha1sum >/dev/null 2>&1; then printf '%s' "$1" | sha1sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum | cut -d' ' -f1
    else printf '%s' "$1" | cksum | tr -d ' '; fi
}
deja_faite()   { [[ "$REPRENDRE" == "true" && -r "$ETAT" ]] && grep -qxF "$1" "$ETAT" 2>/dev/null; }
marquer_faite() { [[ "$SIMULATION" == "true" ]] || printf '%s\n' "$1" >> "$ETAT" 2>/dev/null || true; }

printf '\n'; regle "$GRAS"
printf ' %s%s%s  %s%s%s\n' "$GRAS" "$NOM_SCRIPT" "$C0" "$CYAN" "$SUJET" "$C0"
regle "$GRAS"
for l in ${DETAILS[@]+"${DETAILS[@]}"}; do entete "${l%%=*}" "${l#*=}"; done
entete "sortie"   "${DIR_LOGS%/*}$( (( CREES > 0 )) && printf '  (%d dossier%s créé%s)' "$CREES" "$(pluriel "$CREES")" "$(pluriel "$CREES")")"
entete "par"      "$OPERATEUR"
entete "journal"  "$LOG"
[[ -n "$CONF" ]]                 && entete "config"     "$CONF"
[[ "$SIMULATION" == "true" ]]    && entete "simulation" "rien ne sera exécuté"
[[ "$SANS_QUESTION" == "true" ]] && entete "-y"         "aucune question ne sera posée"
[[ "$TOUT_VALIDER" == "true" ]]  && entete "-v"         "chaque étape sera confirmée"
[[ "$REPRENDRE" == "true" ]]     && entete "reprise"    "les étapes déjà réussies seront sautées"
[[ -n "$FILTRE_ETAPES" ]]        && entete "filtre"     "étapes $FILTRE_ETAPES"
(( DEPUIS > 0 ))                 && entete "depuis"     "$DEPUIS"
[[ -n "$INTRO" ]] && printf '\n%s\n' "$INTRO"
journal "=== démarrage — $SUJET — par $OPERATEUR"
plan_initial


# --- 5.9 Boucle principale -------------------------------------------
NUM=0; NB_FILTREES=0
for entree in "${COMMANDES[@]}"; do
    NUM=$(( NUM + 1 ))
    TITRE="${entree%%|*}"; RESTE="${entree#*|}"; BRUTE="${RESTE#*|}"
    analyser_validation "${RESTE%%|*}"
    etape_retenue "$NUM" || { NB_FILTREES=$(( NB_FILTREES + 1 )); continue; }

    CLE="$(empreinte "$TITRE|$BRUTE")"
    if deja_faite "$CLE"; then
        titre_etape "$NUM" "$TOTAL" "$TITRE"; info "déjà réussie précédemment — sautée (--reprendre)"
        RECAP+=("$NUM|skip|reprise|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); continue
    fi

    titre_etape "$NUM" "$TOTAL" "$TITRE"
    INTERROMPU=0; ETAPE_PASSEE=0
    if ! resoudre_simples "$BRUTE"; then
        RECAP+=("$NUM|skip|passee|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); journal "PASSÉE : $TITRE"; continue
    fi
    CMDBASE="$CMD"; BESOIN_EXP=1

    while true; do
        if (( BESOIN_EXP )); then
            expanser "$CMDBASE"; RCEXP=$?; BESOIN_EXP=0
            if (( ETAPE_PASSEE )); then
                RECAP+=("$NUM|skip|passee|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); journal "PASSÉE : $TITRE"; break
            fi
            if (( INTERROMPU )); then
                INTERROMPU=0; attention "lecture des listes interrompue — étape abandonnée"
                RECAP+=("$NUM|int|listes|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); break
            fi
            if (( RCEXP != 0 || ${#EXP_CMDS[@]} == 0 )); then
                erreur "les listes de cette étape n'ont rien donné : rien à exécuter."
                info "vérifiez la commande de liste (--vars), ou figez-la avec --liste"
                RECAP+=("$NUM|ko|liste vide|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                if [[ "$SANS_QUESTION" != "true" ]]; then
                    menu "Entrée=passer à la suite" "r=ressaisir les valeurs" "q=quitter"
                    CHOIX=""; lire "$(invite)" CHOIX
                    case "${CHOIX,,}" in
                        r) oublier_valeurs "$BRUTE"
                           if resoudre_simples "$BRUTE"; then
                               CMDBASE="$CMD"; BESOIN_EXP=1; unset 'RECAP[-1]'; NB_KO=$(( NB_KO - 1 )); continue
                           fi ;;
                        q) quitter 1 ;;
                    esac
                fi
                break
            fi
        fi

        N=${#EXP_CMDS[@]}; REPETEE=0
        [[ $N -gt 1 || -n "${EXP_LABELS[0]}" ]] && REPETEE=1
        if (( REPETEE )); then resume_iterations; else afficher_commande "${EXP_CMDS[0]}"; fi
        (( F_LOG ))     && info "la sortie est recopiée dans le journal"
        (( F_STOP ))    && info "un échec ici arrête le script"
        (( F_CONTINU )) && info "un échec ici est ignoré, sans question"

        CHOIX=""   # vide = exécuter : les étapes « false » partent seules
        if [[ "$F_VALIDER" == "true" || "$TOUT_VALIDER" == "true" ]]; then
            if (( REPETEE )); then menu "Entrée=tout exécuter" "u=une par une" "l=lister" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"
            else menu "Entrée=exécuter" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"; fi
            lire "$(invite)" CHOIX
        fi

        case "${CHOIX,,}" in
            ""|o|y|u|t)
                UNE_PAR_UNE=0; [[ "${CHOIX,,}" == "u" ]] && UNE_PAR_UNE=1
                executer_groupe "$UNE_PAR_UNE" "$REPETEE"
                (( REPETEE && ${#ITERS[@]} > 0 )) && ENFANTS["$NUM"]="$(printf '%s\x01' "${ITERS[@]}")"

                if (( REPETEE )); then
                    if [[ "$SIMULATION" == "true" ]]; then RECAP+=("$NUM|sim|$N iter|$TITRE")
                    elif (( G_KO == 0 && G_INT == 0 && G_SKIP == 0 )); then
                        RECAP+=("$NUM|ok|$G_OK/$N$( (( EXP_TRONQUE )) && printf ' tronq') $(duree "$G_DUREE")|$TITRE"); NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"
                    elif (( G_KO > 0 )); then RECAP+=("$NUM|ko|$G_KO KO /$N|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                    else RECAP+=("$NUM|int|$G_OK/$N ok|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); fi
                    BILAN="$C_OK$G_OK réussie$(pluriel "$G_OK")$C0"
                    (( G_KO ))   && BILAN+=" · $C_KO$G_KO échec$(pluriel "$G_KO")$C0"
                    (( G_INT ))  && BILAN+=" · $C_WARN$G_INT interrompue$(pluriel "$G_INT")$C0"
                    (( G_SKIP )) && BILAN+=" · $ESTOMPE$G_SKIP passée$(pluriel "$G_SKIP")$C0"
                    printf '\n  %s└─%s  %s · %s%s%s\n' "$ESTOMPE" "$C0" "$BILAN" "$ESTOMPE" "$(duree "$G_DUREE")" "$C0"
                elif (( G_INT )); then
                    RECAP+=("$NUM|int|$(duree "$G_DUREE")|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 ))
                    (( G_ARRET )) || demander_oui_non "  Passer à l'étape suivante ? ${ESTOMPE}[O/n]${C0} " || quitter 130
                elif (( G_KO )); then RECAP+=("$NUM|ko|code $G_RC|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                elif [[ "$SIMULATION" == "true" ]]; then RECAP+=("$NUM|sim|simulee|$TITRE")
                else RECAP+=("$NUM|ok|$(duree "$G_DUREE")|$TITRE"); NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"; fi
                (( G_ARRET == 2 )) && quitter 1
                break ;;
            l) lister_iterations ;;
            p) printf '  %s⊘  passée%s\n' "$ESTOMPE" "$C0"; RECAP+=("$NUM|skip|passee|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); journal "PASSÉE : $TITRE"; break ;;
            e)  # modification pour cette exécution seulement
                NOUVELLE=""; lire_edit "$CMDBASE" NOUVELLE
                if [[ -z "${NOUVELLE// /}" ]]; then attention "commande vide : édition annulée"
                elif resoudre_simples "$NOUVELLE"; then CMDBASE="$CMD"; BESOIN_EXP=1
                else attention "édition annulée"; fi ;;
            r)  # ressaisir les valeurs de CETTE étape seulement
                oublier_valeurs "$BRUTE"
                if resoudre_simples "$BRUTE"; then CMDBASE="$CMD"; BESOIN_EXP=1; info "valeurs ressaisies"
                else RECAP+=("$NUM|skip|passee|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); break; fi ;;
            q) quitter 0 ;;
            *) printf '  %s« %s » n'"'"'est pas une réponse attendue%s\n' "$JAUNE" "$CHOIX" "$C0" ;;
        esac
    done
done

if (( NB_FILTREES == TOTAL )); then
    attention "aucune étape retenue : --seulement / --depuis les écartent toutes"
elif (( NB_FILTREES > 0 )); then
    info "$NB_FILTREES étape(s) écartée(s) par --seulement / --depuis"
fi
(( NB_KO > 0 )) && exit 1
exit 0
