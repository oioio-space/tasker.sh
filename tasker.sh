#!/usr/bin/env bash
#
# tasker.sh — enchaîne des commandes, validées une à une.
#     ./tasker.sh -h       aide          ./tasker.sh -h tout  tout le manuel
#
#   Sections, de la plus retouchée à la moins retouchée :
#   1 VARIABLES · 2 RÉGLAGES · 3 COMMANDES · 4 LISTES · 5 FONCTIONS
#   6 CHEMINS ET CONTRÔLES · 7 BOÎTE À OUTILS · 8 MÉCANIQUE
#
#   Un nom qui commence par TK_ est lu par le script : remplissez-le, ne le
#   supprimez pas, ne le renommez pas. Un nom qui commence par _ est un
#   rouage : le script s'en sert entre deux étapes, laissez-le tranquille.
#   Le reste des noms est à vous.
#   Voir aussi TUTORIEL.md.
#
set -uo pipefail
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}" -lt 43 ]; then
    printf 'bash 4.3 ou plus est requis (trouvé : %s)\n' "${BASH_VERSION:-?}" >&2; exit 1
fi


# =====================================================================
# 1. VARIABLES     ce qui change d'un usage à l'autre
#                  aussi : -c fichier.conf, ou --set NOM=valeur
# =====================================================================
DOSSIER="$HOME"                # ce sur quoi on travaille
SORTIE="${TMPDIR:-/tmp}/tasker" # où écrire journal et rapport


# =====================================================================
# 2. RÉGLAGES      posés une fois, rarement retouchés
# =====================================================================
TK_REQUIS=(du df)              # binaires attendus ; absents = avertissement
TK_OPERATEUR="${SUDO_USER:-${USER:-inconnu}}"   # noté au journal et au rapport
TK_TOUT_VALIDER="false"        # true = confirmer chaque étape (ou -a)
TK_MAX_ITERATIONS=500          # au-delà, une étape répétée est tronquée


# =====================================================================
# 3. COMMANDES     "Titre|validation|commande"
#
#   validation  true = demander avant de lancer, false = lancer direct ;
#               puis, séparées par des virgules : log (sortie au journal ;
#               la commande tourne alors dans un sous-shell, un cd n'y
#               persiste pas), continu (un échec n'arrête rien), stop (un
#               échec arrête tout)
#   $VAR        remplacée maintenant ; \$ pour qu'elle survive jusqu'à
#               l'exécution :  for f in *; do echo \$f; done
#   [[nom]]     une valeur demandée une fois, réutilisée partout
#   {{nom}}     l'étape est rejouée pour chaque valeur de la liste « nom »
#               Les deux TOUJOURS entre apostrophes : '[[nom]]' '{{nom}}'.
#               C'est ce qui rend une valeur inoffensive quoi qu'elle
#               contienne — un nom de fichier lu sur un disque, par exemple.
#   Pas de | dans le titre ; ceux de la commande sont libres.
#   Le tout est dans une fonction pour que $DOSSIER etc. suivent -c et --set.
#
#   Ce qui suit est un exemple qui tourne partout. Remplacez-le, ou
#   laissez-le et mettez les vôtres dans un fichier -c (voir exemples/).
# =====================================================================
definir_commandes() {

TK_COMMANDES=(
"Espace disponible|false|df -h '$DOSSIER'"
"Contenu du dossier|true|ls -la '$DOSSIER'"
"Taille de chaque sous-dossier|true|du -sh '{{sousdossier}}'"
"Fichiers plus gros que [[taille]]|true,log|find '$DOSSIER' -type f -size +'[[taille]]' 2>/dev/null | tail -n 20"
)


# =====================================================================
# 4. LISTES        "nom|commande qui écrit une valeur par ligne"
#
#   [[nom]] dans une commande -> menu numéroté, une valeur choisie
#   {{nom}} dans une commande -> l'étape est rejouée pour chaque valeur
#
#   Une ligne  valeur<TAB>libellé  envoie la valeur dans la commande et
#   affiche le libellé, disponible en {{nom_libelle}}.
#
#   UNE LISTE PEUT EN APPELER UNE AUTRE, et c'est tout le mécanisme : une
#   liste qui contient {{sousdossier}} est régénérée pour chaque
#   sous-dossier, et l'écrire seule dans une commande suffit à parcourir
#   les deux niveaux. Une liste vide ne produit aucune itération, ce n'est
#   pas une erreur. Exemple déroulé : TUTORIEL.md.
# =====================================================================
TK_LISTES=(
"sousdossier|lister_dossiers '$DOSSIER'"
"taille|printf '%s\t%s\n' 1M 'un mégaoctet' 10M 'dix mégaoctets' 100M 'cent mégaoctets'"
)

}


# =====================================================================
# 5. FONCTIONS
#    Une fonction d'étape termine par return (son code fait ● ou ✗).
#    Une fonction de liste écrit une valeur par ligne, ses erreurs sur >&2.
#    Dans une boucle longue :  (( INTERROMPU )) && return 130
# =====================================================================

# Les listes courantes sont déjà écrites en section 7 : lister_dossiers,
# lister_fichiers, lister_arbre, lister_si_present, lister_lignes,
# lister_utilisateurs. Ici, les vôtres.
#
# Exemple : filtrer ce qu'une fonction fournie renvoie. Les deux règles
# tiennent en deux lignes — emettre écrit la valeur, et toute boucle un
# peu longue laisse Ctrl-C sortir.
lister_gros_dossiers() {          # <racine> [Mo mini, 100 par défaut]
    local d taille
    while IFS=$'\t' read -r d _; do
        (( INTERROMPU )) && return 130
        taille="$(du -sm "$d" 2>/dev/null | cut -f1)"
        (( ${taille:-0} >= ${2:-100} )) && emettre "$d" "${d##*/} — ${taille} Mo"
    done < <(lister_dossiers "$1")
    return 0
}


# =====================================================================
# 6. CHEMINS ET CONTRÔLES     ce que la mécanique attend de vous
# =====================================================================

# Recalculé après -c et --set. Quatre noms sont attendus, le reste vous
# appartient :
#   TK_SUJET    titre court, en tête et au récapitulatif
#   TK_DETAILS  lignes du bandeau de départ, "clé=valeur" (clé sans accent)
#   TK_PREFIX   préfixe des fichiers écrits
#   TK_DIR_xxx  dossiers de travail, vérifiés et créés au besoin.
#            TK_DIR_LOGS reçoit le journal, le rapport et l'état de reprise.
calculer_variables() {
    TK_SUJET="${DOSSIER##*/}"
    TK_DETAILS=("dossier=$DOSSIER")
    TK_PREFIX="$(printf '%s' "${DOSSIER##*/}" | tr -c 'A-Za-z0-9._-' '_')"
    TK_DIR_LOGS="$SORTIE/logs"
}

# Contrôles avant de commencer : renvoyez 1 pour arrêter. Les dossiers et
# les binaires de TK_REQUIS sont déjà vérifiés par ailleurs.
verifier() {
    [[ -d "$DOSSIER" ]] || { erreur "dossier absent : $DOSSIER"
        info "réglez DOSSIER en section 1, ou : --set DOSSIER=/chemin · -c fichier.conf"
        return 1; }
    return 0
}


# =====================================================================
# 7. BOÎTE À OUTILS     fournies avec le script : à appeler, pas à modifier
# =====================================================================

# Toutes les fonctions ci-dessous suivent le même contrat : une valeur par
# ligne sur la sortie standard, « valeur<TAB>libellé », les messages sur
# >&2 (ils vont au journal), et rien n'est une erreur quand il n'y a
# simplement rien à lister.
#
# Les motifs sont facultatifs et multiples. Ils portent sur le NOM seul,
# jamais sur le chemin, comme find -name, et distinguent les majuscules ;
# -i juste avant les arguments les ignore.

# emettre <valeur> [libellé]
# Le seul endroit qui écrit une ligne. Écarte ce que la mécanique ne
# saurait pas relire. Rend 1 si la valeur a été écartée.
emettre() {
    local val="${1-}" lib="${2-}"
    [[ -n "$val" ]] || return 1
    case "$val$lib" in
        *$'\n'*) printf 'valeur ignorée, retour à la ligne dans le nom : %q\n' "$val" >&2; return 1 ;;
    esac
    case "$val" in
        *$'\t'*)       printf 'valeur ignorée, tabulation dans le nom : %q\n' "$val" >&2; return 1 ;;
        *'[['*|*'{{'*) printf 'valeur ignorée, contient [[ ou {{ : %s\n'      "$val" >&2; return 1 ;;
    esac
    lib="${lib//$'\t'/ }"
    if [[ -n "$lib" ]]; then printf '%s\t%s\n' "$val" "$lib"
    else                     printf '%s\n'     "$val"; fi
}

# _opts <args...>    interne : lit les options de tête, pose _I et _OPTN
# L'appelant déclare « local _I _OPTN » puis fait « shift "$_OPTN" ».
_opts() {
    _I=0; _OPTN=0
    while [[ "${1-}" == -? || "${1-}" == "--" ]]; do
        case "$1" in
            -i) _I=1 ;;
            --) _OPTN=$(( _OPTN + 1 )); return 0 ;;
            *)  printf '%s : option inconnue : %s\n' "${FUNCNAME[1]}" "$1" >&2; return 1 ;;
        esac
        shift; _OPTN=$(( _OPTN + 1 ))
    done
    return 0
}

# _colle <nom> <motif>   interne : le nom correspond-il au motif ?
_colle() {
    # shellcheck disable=SC2053  # motif volontairement non protégé
    if (( ${_I:-0} )); then [[ "${1,,}" == ${2,,} ]]; else [[ "$1" == $2 ]]; fi
}

# _motifs [motif...]   interne : pose _MOTIFS, sans les motifs vides
# Un motif vide vaut « pas de motif » : une variable non renseignée dans un
# fichier -c ne doit pas faire disparaître la liste en silence.
_motifs() {
    local m; _MOTIFS=()
    for m in ${@+"$@"}; do [[ -n "$m" ]] && _MOTIFS+=( "$m" ); done
    (( ${#_MOTIFS[@]} )) || _MOTIFS=( '*' )
}

# _entrees <d|f> <racine> [motif...]    interne : lister_dossiers/fichiers
_entrees() {
    local genre="${1-}" qui="${FUNCNAME[1]}" brut="${2-}" racine="${2-}"
    local e nom m
    [[ -n "$brut" ]] || { printf '%s : il faut un dossier en argument\n' "$qui" >&2; return 1; }
    racine="${racine%/}" ; [[ -n "$racine" ]] || racine="/"   # « / » reste « / »
    shift 2
    local -a _MOTIFS; _motifs ${@+"$@"}
    [[ -d "$racine" ]] || { printf '%s : pas un dossier, ignoré : %s\n' "$qui" "$brut" >&2; return 0; }
    [[ -r "$racine" && -x "$racine" ]] || { printf '%s : dossier illisible, ignoré : %s\n' "$qui" "$brut" >&2; return 0; }
    # Aucun shopt à poser : un motif qui ne trouve rien reste tel quel et
    # le test -e l'écarte. L'état du shell n'est pas touché.
    for e in "${racine%/}"/* "${racine%/}"/.*; do
        (( INTERROMPU )) && return 130
        [[ -e "$e" || -L "$e" ]] || continue
        nom="${e##*/}"
        [[ "$nom" == "." || "$nom" == ".." ]] && continue
        case "$genre" in
            d) [[ -d "$e" ]] || continue ;;
            f) [[ -f "$e" ]] || continue ;;
        esac
        for m in "${_MOTIFS[@]}"; do
            _colle "$nom" "$m" && { emettre "$e" "$nom"; break; }
        done
    done
    return 0
}

# lister_dossiers [-i] <racine> [motif...]   les sous-dossiers directs
#   lister_dossiers /srv            lister_dossiers /srv 'prod-*' 'test-*'
lister_dossiers() { local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"; _entrees d "$@"; }

# lister_fichiers [-i] <racine> [motif...]   les fichiers directs
#   lister_fichiers /var/log '*.log'         lister_fichiers -i /docs '*.PDF'
lister_fichiers() { local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"; _entrees f "$@"; }

# lister_arbre [-i] <racine> [motif...]   les fichiers de toute l'arborescence
# Libellé = chemin relatif à la racine. Ne suit pas les liens vers des
# dossiers : aucune boucle possible.
#   lister_arbre /etc '*.conf'
lister_arbre() {
    local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"
    local brut="${1-}" racine="${1-}"
    [[ -n "$brut" ]] || { printf 'lister_arbre : il faut un dossier en argument\n' >&2; return 1; }
    racine="${racine%/}" ; [[ -n "$racine" ]] || racine="/"   # « / » reste « / »
    shift
    [[ -d "$racine" ]] || { printf 'lister_arbre : pas un dossier, ignoré : %s\n' "$brut" >&2; return 0; }
    local -a _MOTIFS; _motifs ${@+"$@"}
    _arbre "$racine" "$racine" "${_MOTIFS[@]}"
}
_arbre() {
    local racine="$1" dir="$2" ; shift 2
    local e nom m
    [[ -r "$dir" && -x "$dir" ]] || { printf 'lister_arbre : dossier illisible, ignoré : %s\n' "$dir" >&2; return 0; }
    for e in "${dir%/}"/* "${dir%/}"/.*; do
        (( INTERROMPU )) && return 130
        [[ -e "$e" || -L "$e" ]] || continue
        nom="${e##*/}"
        [[ "$nom" == "." || "$nom" == ".." ]] && continue
        if [[ -d "$e" && ! -L "$e" ]]; then
            _arbre "$racine" "$e" "$@" || return $?
        elif [[ -f "$e" ]]; then
            for m in "$@"; do
                _colle "$nom" "$m" && { emettre "$e" "${e#"${racine%/}/"}"; break; }
            done
        fi
    done
    return 0
}

# _trouver <critère...> -- <racine> [motif...]   interne : lister_recents/gros
_trouver() {
    local qui="${FUNCNAME[1]}"
    local -a crit=()
    while (( $# )) && [[ "$1" != "--" ]]; do crit+=( "$1" ); shift; done
    shift
    local brut="${1-}" racine="${1-}"
    racine="${racine%/}" ; [[ -n "$racine" ]] || racine="/"   # « / » reste « / »
    shift
    local -a _MOTIFS; _motifs ${@+"$@"}
    local f nom m
    [[ -d "$racine" ]] || { printf '%s : pas un dossier, ignoré : %s\n' "$qui" "$brut" >&2; return 0; }
    command -v find >/dev/null 2>&1 || { printf '%s : find introuvable\n' "$qui" >&2; return 0; }
    while IFS= read -r -d '' f; do
        (( INTERROMPU )) && return 130
        nom="${f##*/}"
        for m in "${_MOTIFS[@]}"; do
            _colle "$nom" "$m" && { emettre "$f" "${f#"${racine%/}/"}"; break; }
        done
    done < <(find "$racine" -type f "${crit[@]}" -print0 2>/dev/null)
    return 0
}

# lister_recents [-i] <racine> <jours> [motif...]   modifiés depuis N jours
#   lister_recents /var/log 2 '*.log'
lister_recents() {
    local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"
    local racine="${1-}" jours="${2-}"
    [[ -n "$racine" && -n "$jours" ]] || { printf 'lister_recents : il faut <racine> <jours>\n' >&2; return 1; }
    [[ "$jours" =~ ^[0-9]+$ ]] || { printf 'lister_recents : jours doit être un entier : %s\n' "$jours" >&2; return 1; }
    shift 2
    _trouver -mtime "-$(( 10#$jours ))" -- "$racine" "$@"
}

# lister_gros [-i] <racine> <Mo> [motif...]   fichiers de plus de N Mo
#   lister_gros /home 100
lister_gros() {
    local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"
    local racine="${1-}" mo="${2-}"
    [[ -n "$racine" && -n "$mo" ]] || { printf 'lister_gros : il faut <racine> <Mo>\n' >&2; return 1; }
    [[ "$mo" =~ ^[0-9]+$ ]] || { printf 'lister_gros : Mo doit être un entier : %s\n' "$mo" >&2; return 1; }
    shift 2
    _trouver -size "+$(( 10#$mo * 1048576 ))c" -- "$racine" "$@"
}

# lister_si_present <chemin>...   ne garde que ce qui existe
# Le compagnon des listes emboîtées : un profil sans le fichier cherché ne
# produit aucune itération, au lieu d'une commande qui échoue.
#   lister_si_present '{{compte}}/.bash_history'
lister_si_present() {
    local c
    for c in ${@+"$@"}; do
        (( INTERROMPU )) && return 130
        [[ -e "$c" || -L "$c" ]] && emettre "$c" "${c##*/}"
    done
    return 0
}

# lister_lignes [-i] <fichier> [motif...]   une valeur par ligne d'un fichier
# Saute les lignes vides et celles qui commencent par #, retire les espaces
# autour et le retour chariot des fichiers Windows. Une ligne
# « valeur<TAB>libellé » garde son libellé.
#   lister_lignes ./serveurs.txt
lister_lignes() {
    local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"
    local fichier="${1-}" ligne val lib m
    [[ -n "$fichier" ]] || { printf 'lister_lignes : il faut un fichier en argument\n' >&2; return 1; }
    shift
    local -a _MOTIFS; _motifs ${@+"$@"}
    [[ -f "$fichier" && -r "$fichier" ]] || { printf 'lister_lignes : fichier illisible, ignoré : %s\n' "$fichier" >&2; return 0; }
    while IFS= read -r ligne || [[ -n "$ligne" ]]; do
        (( INTERROMPU )) && return 130
        ligne="${ligne%$'\r'}"
        ligne="${ligne#"${ligne%%[![:space:]]*}"}"
        ligne="${ligne%"${ligne##*[![:space:]]}"}"
        [[ -z "$ligne" || "$ligne" == '#'* ]] && continue
        val="${ligne%%$'\t'*}" ; lib=""
        [[ "$ligne" == *$'\t'* ]] && lib="${ligne#*$'\t'}"
        for m in "${_MOTIFS[@]}"; do
            _colle "$val" "$m" && { emettre "$val" "$lib"; break; }
        done
    done < "$fichier"
    return 0
}

# lister_colonne <fichier> <n> [séparateur]   la colonne n d'un CSV
# Valeur = la colonne demandée, libellé = la ligne entière, pour voir le
# contexte dans le menu. Séparateur : la virgule par défaut, $'\t' pour un
# TSV, ':' pour /etc/passwd. Une ligne d'en-tête est une valeur comme les
# autres : mettez un # devant dans le fichier.
#   lister_colonne ./postes.csv 2
lister_colonne() {
    local fichier="${1-}" n="${2-}" sep="${3:-,}"
    local ligne val reste i
    [[ -n "$fichier" && -n "$n" ]] || { printf 'lister_colonne : il faut <fichier> <n>\n' >&2; return 1; }
    [[ "$n" =~ ^[0-9]+$ ]] && (( 10#$n >= 1 )) || { printf 'lister_colonne : n doit être un entier ≥ 1 : %s\n' "$n" >&2; return 1; }
    [[ -f "$fichier" && -r "$fichier" ]] || { printf 'lister_colonne : fichier illisible, ignoré : %s\n' "$fichier" >&2; return 0; }
    while IFS= read -r ligne || [[ -n "$ligne" ]]; do
        (( INTERROMPU )) && return 130
        ligne="${ligne%$'\r'}"
        [[ -z "$ligne" || "$ligne" == '#'* ]] && continue
        # Pas de read -a : avec une tabulation en séparateur il fondrait
        # les cellules vides et décalerait les colonnes.
        reste="$ligne"; i=1
        while (( i < 10#$n )) && [[ "$reste" == *"$sep"* ]]; do reste="${reste#*"$sep"}"; i=$(( i + 1 )); done
        if (( i < 10#$n )); then val=""; else val="${reste%%"$sep"*}"; fi
        [[ -n "$val" ]] && emettre "$val" "$ligne"
    done < "$fichier"
    return 0
}

# lister_utilisateurs [uid_mini]   les comptes qui ont un vrai dossier
# Valeur = le dossier personnel — c'est ce dont les commandes ont besoin ;
# libellé = le nom du compte. uid_mini vaut 1000 : les comptes humains sur
# la plupart des Linux, 0 pour tout prendre. Lit /etc/passwd ; ailleurs
# (macOS), écrivez la vôtre avec dscl.
#   lister_utilisateurs        lister_utilisateurs 0
lister_utilisateurs() {
    local mini="${1:-1000}" nom uid home shell
    [[ "$mini" =~ ^[0-9]+$ ]] || { printf 'lister_utilisateurs : uid_mini doit être un entier : %s\n' "$mini" >&2; return 1; }
    [[ -r /etc/passwd ]] || { printf 'lister_utilisateurs : /etc/passwd illisible\n' >&2; return 0; }
    while IFS=: read -r nom _ uid _ _ home shell; do
        (( INTERROMPU )) && return 130
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( 10#$uid >= 10#$mini )) || continue
        [[ -d "$home" ]] || continue
        case "$shell" in */nologin|*/false|*/sync) continue ;; esac
        emettre "$home" "$nom"
    done < /etc/passwd
    return 0
}

# lister_montages [-i] [motif...]   les systèmes de fichiers montés
# Seulement ceux qui viennent d'un périphérique — les montages internes du
# noyau (proc, sysfs, cgroup, tmpfs) sont écartés. Valeur = le point de
# montage, libellé = type et périphérique. Lit /proc/mounts, donc Linux.
#   lister_montages            lister_montages '/mnt/*'
lister_montages() {
    local _I _OPTN; _opts "$@" || return 1; shift "$_OPTN"
    local -a _MOTIFS; _motifs ${@+"$@"}
    local dev pt type m
    [[ -r /proc/mounts ]] || { printf 'lister_montages : /proc/mounts illisible, Linux seulement\n' >&2; return 0; }
    while read -r dev pt type _; do
        (( INTERROMPU )) && return 130
        [[ "$dev" == /* ]] || continue
        # /proc/mounts échappe l'espace en \040 : %b le relit.
        dev="$(printf '%b' "$dev")" ; pt="$(printf '%b' "$pt")"
        for m in "${_MOTIFS[@]}"; do
            _colle "$pt" "$m" && { emettre "$pt" "$type · $dev"; break; }
        done
    done < /proc/mounts
    return 0
}


# =====================================================================
# 8. MÉCANIQUE
# =====================================================================

# --- 8.1 Affichage ---------------------------------------------------
_COULEUR="auto"
# Posé tôt : la boîte à outils le teste, et un fichier -c peut appeler une
# de ses fonctions depuis calculer_variables, bien avant la boucle.
INTERROMPU=0; EN_SAISIE=0
# Valeurs sûres tant que init_affichage n'a pas tourné.
C0=""; GRAS=""; ESTOMPE=""; COULEURS=0
C_ACCENT=""; C_OK=""; C_KO=""; C_WARN=""; C_SIM=""; C_PROG=""; C_CMD=""
C_BOUCLE=""; C_CLE=""; C_BOITE=""; C_TITRE=""; SORTIE_GRISE=""
_LARGEUR=80; _LARGEUR_TTY=80
NOM_SCRIPT="${0##*/}"

# Jamais de couleur de fond, jamais de gris fixe : « estompé » est
# l'attribut faint, qui suit le thème du terminal, clair ou sombre. Sur un
# terminal 256 couleurs la palette est adoucie — une accent chaude pour
# l'étape en cours, des teintes calmes pour les états.
teinte() { (( COULEURS >= 256 )) && printf '\033[38;5;%dm' "$1" || printf '%s' "$2"; }
init_affichage() {
    local actif="non"
    case "$_COULEUR" in
        oui)  actif="oui" ;;
        auto) [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]] && actif="oui" ;;
    esac
    COULEURS=8
    if [[ "$actif" == "oui" ]]; then
        C0=$'\033[0m'; GRAS=$'\033[1m'; ESTOMPE=$'\033[2m'
        ROUGE=$'\033[31m'; VERT=$'\033[32m'; JAUNE=$'\033[33m'
        BLEU=$'\033[34m'; MAGENTA=$'\033[35m'; CYAN=$'\033[36m'
        COULEURS="$(tput colors 2>/dev/null || printf 8)"
        [[ "$COULEURS" =~ ^[0-9]+$ ]] || COULEURS=8
    else
        C0=""; GRAS=""; ESTOMPE=""; ROUGE=""; VERT=""; JAUNE=""; BLEU=""; MAGENTA=""; CYAN=""
        COULEURS=0
    fi
    # Une couleur par rôle.
    C_ACCENT="$(teinte 173 "$JAUNE")"  # l'étape en cours : le fil conducteur
    C_OK="$(teinte 108 "$VERT")"
    C_KO="$GRAS$(teinte 167 "$ROUGE")"
    C_WARN="$(teinte 179 "$JAUNE")"
    C_SIM="$(teinte 109 "$BLEU")"
    C_PROG="$GRAS$(teinte 109 "$CYAN")" # le programme lancé
    C_CMD=""                            # ses arguments : rien, la sobriété
    C_BOUCLE="$(teinte 139 "$MAGENTA")" # étiquettes d'itération  agent=alice
    C_CLE="$GRAS"                       # touches des menus
    C_BOITE="$(teinte 109 "$BLEU")"     # cadre des questions
    C_TITRE="$GRAS$C_ACCENT"            # bandeaux Plan / Récapitulatif
    # La sortie d'une commande est estompée : ce qui compte à l'écran, ce
    # sont les étapes. Un programme qui pose ses propres couleurs reprend
    # la main, on ne lutte pas contre lui.
    SORTIE_GRISE="$ESTOMPE"
    suivre_fenetre
    init_glyphes
}

# La largeur du terminal. tput la demande par un ioctl sur la sortie
# d'erreur : le 2>/dev/null qu'il faut bien lui mettre lui fait rendre la
# valeur du terminfo — 80, quelle que soit la fenêtre. On la demande donc à
# stty, et COLUMNS passe devant quand il est posé, ce qui laisse la forcer.
# Appelée entre deux étapes : la fenêtre a pu changer de taille. Pas de
# [[ =~ ]] ici, il écraserait le BASH_REMATCH d'un appelant.
suivre_fenetre() {
    local taille cols="${COLUMNS:-}"      # posé à la main : il gagne
    if [[ -z "$cols" && -t 1 ]]; then
        taille="$(stty size 2>/dev/null < /dev/tty)"
        cols="${taille#* }"
    fi
    case "$cols" in ''|*[!0-9]*) cols=80 ;; esac
    _LARGEUR_TTY="$cols"        # celle du terminal, avant la borne à 100 de la mise en page
    _LARGEUR="$cols"
    poser_largeur
    return 0
}

# Sous une locale POSIX, ${#x} compte les octets : « é » en vaut deux, les
# colonnes se décalent et un repli peut couper un caractère en deux. On
# essaie d'abord de passer bash lui-même en UTF-8 — LC_ALL n'est pas
# exporté, vos commandes gardent leur locale — et sinon on mesure à la main.
_SONDE="é"; _UTF8_OK=0
for _loc in "" C.UTF-8 C.utf8 en_US.UTF-8 fr_FR.UTF-8; do
    [[ -n "$_loc" ]] && LC_ALL="$_loc"
    (( ${#_SONDE} == 1 )) && { _UTF8_OK=1; break; }
done
(( _UTF8_OK )) || unset LC_ALL
LC_ALL_TK="${LC_ALL-__absent__}"   # pour la remettre si une commande la change
unset _SONDE _loc
# --- primitives d'affichage ------------------------------------------
# Elles écrivent dans une variable au lieu de rendre par $( ) : chaque
# substitution est un fork, et une étape en demandait une trentaine.

# largeur_texte <texte> -> LARG_TXT, la place prise à l'écran.
# Un idéogramme ou un emoji occupe deux colonnes, un accent combinant zéro.
# Le chemin rapide sert au cas courant : du texte sans accent ni symbole.
# Avec une limite, POS_COUPE dit où couper pour tenir dans ce nombre de
# colonnes et LARG_COUPE la largeur atteinte là ; POS_COUPE vaut -1 quand le
# texte tient déjà. C'est la même passe qui mesure et qui repère la coupe :
# « couper » n'a pas à reparcourir le texte.
LARG_TXT=0
POS_COUPE=-1
LARG_COUPE=0
largeur_texte() {
    local t="$1" max="${2--1}" c cp l i=0
    POS_COUPE=-1; LARG_COUPE=0
    if (( ! _UTF8_OK )); then
        # ${#t} compte les octets : on retire ceux de continuation pour
        # mesurer, et la coupe se cherche dans l'original, octet par octet.
        c="${t//[$'\x80'-$'\xbf']/}"; LARG_TXT=${#c}
        if (( max >= 0 && LARG_TXT > max )); then
            LARG_COUPE=0
            while (( LARG_COUPE < max )); do
                i=$(( i + 1 ))
                while [[ "${t:$i:1}" == [$'\x80'-$'\xbf'] ]]; do i=$(( i + 1 )); done
                LARG_COUPE=$(( LARG_COUPE + 1 ))
            done
            POS_COUPE=$i
        fi
        return 0
    fi
    if [[ "$t" != *[$'\x80'-$'\xff']* ]]; then LARG_TXT=${#t}
        (( max >= 0 && LARG_TXT > max )) && { POS_COUPE=$max; LARG_COUPE=$max; }
        return 0
    fi
    LARG_TXT=0
    while [[ -n "$t" ]]; do
        c="${t:0:1}"; t="${t:1}"; i=$(( i + 1 ))
        printf -v cp '%d' "'$c"
        if   (( cp >= 0x0300 && cp <= 0x036F )); then continue                     # accents combinants
        elif (( cp >= 0x1100 && cp <= 0x115F )) \
          || (( cp >= 0x2E80 && cp <= 0x303E )) || (( cp >= 0x3041 && cp <= 0x33FF )) \
          || (( cp >= 0x3400 && cp <= 0x4DBF )) || (( cp >= 0x4E00 && cp <= 0x9FFF )) \
          || (( cp >= 0xA000 && cp <= 0xA4CF )) || (( cp >= 0xAC00 && cp <= 0xD7A3 )) \
          || (( cp >= 0xF900 && cp <= 0xFAFF )) || (( cp >= 0xFE30 && cp <= 0xFE6F )) \
          || (( cp >= 0xFF00 && cp <= 0xFF60 )) || (( cp >= 0xFFE0 && cp <= 0xFFE6 )) \
          || (( cp >= 0x1F300 && cp <= 0x1F9FF )) || (( cp >= 0x1FA70 && cp <= 0x1FAFF )) \
          || (( cp >= 0x20000 && cp <= 0x3FFFD ))
        then l=2
        else l=1; fi
        (( max >= 0 && POS_COUPE < 0 && LARG_TXT + l > max )) && { POS_COUPE=$(( i - 1 )); LARG_COUPE=$LARG_TXT; }
        LARG_TXT=$(( LARG_TXT + l ))
    done
    return 0
}

# repeter <caractère> <n> -> REPET
REPET=""
repeter() {
    if (( $2 <= 0 )); then REPET=""; return 0; fi
    printf -v REPET '%*s' "$2" ''
    [[ "$1" == " " ]] || REPET="${REPET// /$1}"
    return 0
}
# couper <texte> <colonnes> -> COUPE, au plus <colonnes> de large, et LARG_TXT
# Un titre trop long poussait la colonne de droite hors de l'écran.
COUPE=""
couper() {
    local max="$2"
    largeur_texte "$1" $(( max - 1 ))
    (( LARG_TXT <= max )) && { COUPE="$1"; return 0; }
    (( max < 2 ))         && { COUPE=""; LARG_TXT=0; return 0; }
    COUPE="${1:0:POS_COUPE}…"; LARG_TXT=$(( LARG_COUPE + 1 ))
    return 0
}

# pad_droite <texte> <largeur> -> PAD, exactement <largeur> colonnes
# Trop court on complète, trop long on coupe : une colonne reste une colonne,
# et aucun texte ne pousse la colonne suivante hors de l'écran.
PAD=""
pad_droite() {
    local n
    couper "$1" "$2"; n=$(( $2 - LARG_TXT )); (( n < 0 )) && n=0
    printf -v PAD '%s%*s' "$COUPE" "$n" ''
    return 0
}
# _COL_BLOC : la colonne des titres du bloc qu'on affiche. Le détail de droite
# est parfois plus large que d'habitude (« ↻ répétée · auto » au plan) : la
# colonne recule alors d'un coup pour tout le bloc — ligne par ligne, elle
# serait en escalier.
_COL_BLOC=0
poser_colonne() {   # <détail>...
    local d max=0
    for d in ${@+"$@"}; do largeur_texte "$d"; (( LARG_TXT > max )) && max=$LARG_TXT; done
    _COL_BLOC=$(( _LARGEUR - _LARG_NUM - 8 - max ))
    (( _COL_BLOC > _COL_TITRE )) && _COL_BLOC=$_COL_TITRE
    (( _COL_BLOC < 12 )) && _COL_BLOC=12
    return 0
}

# Le filet ne change qu'avec la largeur : il est calculé une fois.
_REGLE_TXT=""
regle()   { printf '%s%s%s\n' "${1:-$ESTOMPE}" "$_REGLE_TXT" "$C0"; }
pluriel() { (( $1 > 1 )) && printf 's'; return 0; }
entete()  { printf '  %s%-10s%s %s\n' "$ESTOMPE" "$1" "$C0" "$2"; }   # clé ASCII
info()      { printf '  %s%s%s\n'     "$ESTOMPE" "$*" "$C0"; }
attention() { printf '  %s⚠  %s%s\n'  "$C_WARN"  "$*" "$C0"; }
erreur()    { printf '%s✗  %s%s\n'    "$C_KO"    "$*" "$C0" >&2; }

BARRE=""
LARG_BARRE=12   # la barre d'avancement, en colonnes
barre() {   # <fait> <total> -> BARRE
    local larg=$LARG_BARRE plein pleine
    plein=$(( $1 * larg / ($2 > 0 ? $2 : 1) ))
    (( plein > larg )) && plein=$larg
    repeter '━' "$plein"; pleine="$REPET"
    repeter '━' $(( larg - plein ))
    BARRE="$C_ACCENT$pleine$ESTOMPE$REPET$C0"
    return 0
}

DUREE_TXT=""
duree() {   # <secondes> -> DUREE_TXT
    if   (( $1 < 60 ));   then printf -v DUREE_TXT '%ds' "$1"
    elif (( $1 < 3600 )); then printf -v DUREE_TXT '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 ))
    else                       printf -v DUREE_TXT '%dh%02dm' $(( $1 / 3600 )) $(( $1 % 3600 / 60 )); fi
    return 0
}

# ○ à faire  ◐ en cours  ● réussie  ✗ échec  ⊘ passée  ⊗ interrompue  ◌ simulée
# Une colonne chacun, jamais d'emoji : ils en prennent deux et cassent l'alignement.
# Les marques colorées sont figées une fois pour toutes : ${GLYPHE[ok]}.
# GLYPHE_TXT sert au rapport, en texte brut et sans accent.
declare -A GLYPHE=() 
declare -A GLYPHE_TXT=(
    [todo]='a faire' [cours]='en cours' [ok]='ok'          [ko]='ECHEC'
    [skip]='passee'  [int]='interrompue' [sim]='simulee'
)
init_glyphes() {
    GLYPHE=(
        [todo]="$ESTOMPE○$C0"   [cours]="$C_ACCENT◐$C0"
        [ok]="$C_OK●$C0"        [ko]="$C_KO✗$C0"
        [skip]="$ESTOMPE⊘$C0"   [int]="$C_WARN⊗$C0"
        [sim]="$C_SIM◌$C0"
    )
}

# Recalculés à chaque changement de largeur, jamais dans une boucle.
_COL_TITRE=52
poser_largeur() {
    (( _LARGEUR < 40 )) && _LARGEUR=40
    (( _LARGEUR > 100 )) && _LARGEUR=100
    _COL_TITRE=$(( _LARGEUR - 22 )); (( _COL_TITRE < 24 )) && _COL_TITRE=24
    (( _COL_TITRE > 52 )) && _COL_TITRE=52
    _COL_BLOC=$_COL_TITRE          # par défaut : une ligne seule tient la colonne
    repeter '─' "$_LARGEUR"; _REGLE_TXT="$REPET"
    return 0
}

_LARG_NUM=2   # largeur des numéros d'étape, recalculée d'après _TOTAL

# remplacer <texte> <motif> <remplacement> -> REMPLACE ; tout est littéral.
# ${t//motif/rempl} ne convient pas : depuis bash 5.2, un « & » dans le
# remplacement y réinsère le texte trouvé. Une valeur comme « Rock & Roll »
# remettait donc le [[nom]] dans la commande, et la boucle qui résout les
# placeholders tournait sans fin.
REMPLACE=""
remplacer() {
    local t="${1-}" m="${2-}" r="${3-}" out=""
    if [[ -z "$m" ]]; then REMPLACE="$t"; return 0; fi
    while [[ "$t" == *"$m"* ]]; do
        out+="${t%%"$m"*}$r"
        t="${t#*"$m"}"
    done
    REMPLACE="$out$t"
}

# Un titre s'affiche avec les [[valeurs]] déjà répondues : « Purge de plus
# de 30 jours » plutôt que « [[jours]] ». Celles qui ne sont pas encore
# connues — au plan, rien ne l'est — restent telles quelles.
titre_lisible() {
    local t="${1-}" reste="${1-}" nom
    t="${t//$'\t'/ }"          # une tabulation dans un titre casserait l'alignement
    while [[ "$reste" =~ $RE_SIMPLE ]]; do
        nom="${BASH_REMATCH[1]}"
        reste="${reste//\[\[$nom\]\]/}"
        [[ -n "${_REPONSES[$nom]:-}" ]] && { remplacer "$t" "[[$nom]]" "${_REPONSES[$nom]}"; t="$REMPLACE"; }
    done
    printf '%s' "$t"
}

ligne_tache() {   # <état> <numéro> <titre> <détail>
    local ct="" t
    t="$(titre_lisible "$3")"
    case "$1" in ko) ct="$C_KO" ;; int) ct="$C_WARN" ;; skip) ct="$ESTOMPE" ;; sim) ct="$C_SIM" ;; esac
    if [[ -z "$4" ]]; then
        couper "$t" $(( _LARGEUR - _LARG_NUM - 6 ))
        printf '  %s %s%*s%s  %s%s%s\n' "${GLYPHE[$1]:- }" "$ESTOMPE" "$_LARG_NUM" "$2" "$C0" "$ct" "$COUPE" "$C0"
    else
        pad_droite "$t" "$_COL_BLOC"
        printf '  %s %s%*s%s  %s%s%s  %s%s%s\n' "${GLYPHE[$1]:- }" "$ESTOMPE" "$_LARG_NUM" "$2" "$C0" \
               "$ct" "$PAD" "$C0" "$ESTOMPE" "$4" "$C0"
    fi
}

titre_etape() {   # <numéro> <total> <titre>
    local rang
    printf '\n'; regle
    barre "$(( $1 - 1 ))" "$2"
    printf -v rang '%d/%d' "$1" "$2"
    couper "$(titre_lisible "$3")" $(( _LARGEUR - 8 - LARG_BARRE - ${#rang} ))
    printf '  %s %s%s%s  %s  %s%s%s\n' "${GLYPHE[cours]}" "$GRAS$C_ACCENT" "$rang" "$C0" \
           "$BARRE" "$GRAS" "$COUPE" "$C0"
    regle
}

# Repliée aux espaces si elle dépasse l'écran : c'est la ligne à relire.
# replier <texte> <largeur> -> LIGNES : coupé aux espaces, par caractères.
# fold ferait l'affaire, mais sous une locale POSIX il compte les octets et
# coupe un « é » en deux.
LIGNES=()
replier() {
    local larg="$2" ligne="" mot brut large=0 lmot=0
    local -a mots=()
    LIGNES=()
    # Une commande peut tenir sur plusieurs lignes : chacune est repliée
    # pour elle-même, aucune n'est perdue. Montrer la première seulement
    # ferait valider une commande dont on n'a pas vu la suite.
    while IFS= read -r brut || [[ -n "$brut" ]]; do
        if [[ -z "${brut//[[:space:]]/}" ]]; then LIGNES+=(""); continue; fi
        ligne=""; mots=(); large=0
        read -r -a mots <<< "$brut"
        for mot in ${mots[@]+"${mots[@]}"}; do
            # La largeur de la ligne se cumule au lieu d'être recalculée à
            # chaque mot : sur du texte accentué, la remesurer coûtait un
            # temps carré du nombre de mots.
            largeur_texte "$mot"; lmot=$LARG_TXT
            if [[ -z "$ligne" ]]; then ligne="$mot"; large=$lmot
            elif (( large + 1 + lmot <= larg )); then ligne+=" $mot"; large=$(( large + 1 + lmot ))
            else LIGNES+=("$ligne"); ligne="$mot"; large=$lmot; fi
            # un mot seul plus large que l'écran : coupé net si l'on sait le
            # faire par caractères, sinon laissé déborder plutôt qu'abîmé
            while (( _UTF8_OK && ${#ligne} > larg )); do
                LIGNES+=("${ligne:0:larg}"); ligne="${ligne:larg}"
                largeur_texte "$ligne"; large=$LARG_TXT
            done
        done
        [[ -n "$ligne" ]] && LIGNES+=("$ligne")
    done <<< "$1"
    return 0
}

afficher_commande() {   # <commande> [indentation]
    local ind="${2:-  }" dispo i prog reste
    # Les lignes de suite sont indentées de quatre espaces de plus que le
    # « $ » de la première : c'est elles qui fixent la place disponible,
    # sinon elles débordaient de deux colonnes.
    dispo=$(( _LARGEUR - ${#ind} - 4 )); (( dispo < 24 )) && dispo=24
    replier "$1" "$dispo"
    for i in "${!LIGNES[@]}"; do
        if (( i == 0 )); then
            prog="${LIGNES[0]%% *}"; reste="${LIGNES[0]#"$prog"}"
            printf '%s%s$%s %s%s%s%s%s%s\n' "$ind" "$ESTOMPE" "$C0" "$C_PROG" "$prog" "$C0" "$C_CMD" "$reste" "$C0"
        else
            printf '%s    %s%s%s\n' "$ind" "$C_CMD" "${LIGNES[$i]}" "$C0"
        fi
    done
}

menu() {   # clé=texte ... — la première clé est celle de la touche Entrée
    local e ligne=""
    [[ "$_SANS_QUESTION" == "true" ]] && return 0
    for e in "$@"; do
        ligne+="${ligne:+$ESTOMPE · $C0}${C_CLE}${e%%=*}${C0} ${ESTOMPE}${e#*=}${C0}"
    done
    printf '  %s\n' "$ligne"
}
invite() { printf '  %s›%s ' "$GRAS" "$C0"; }


# --- 8.2 Aide --------------------------------------------------------
# L'aide : option en cyan, touches en gras, rien d'autre.
h_titre() { printf '\n%s%s%s\n' "$GRAS" "$1" "$C0"; }
h_opt()   { printf '  %s%-26s%s %s\n' "$C_PROG" "$1" "$C0" "$2"; }          # -x, --xx VALEUR   explication
h_cle() {   # <libellé> clé=texte ... — une clé vide n'affiche que le texte
    pad_droite "$1" 16; printf '  %s ' "$PAD"; shift
    local e k s=""
    for e in "$@"; do k="${e%%=*}"; s+="${s:+ · }${k:+$GRAS$k$C0 }${e#*=}"; done
    printf '%s\n' "$s"
}
h_ligne() { printf '  %s\n' "$*"; }
h_code()  { printf '  %s%s%s\n' "$C_PROG" "$*" "$C0"; }
h_vide()  { printf '\n'; }
h_ex()    { printf '  %s%-38s%s %s\n' "$C_PROG" "$1" "$C0" "$2"; }   # code   commentaire

SUJETS="etapes valeurs outils config exemple tout"

aide_etapes() {
    h_titre "Une étape   section 3 du script, ou votre fichier -c"
    h_code '"Titre|validation|commande"'
    h_vide
    h_code '"Espace disque|true|df -h /"'
    h_code '"Sauvegarde|false|tar czf /tmp/etc.tgz /etc"'
    h_code '"Journalisée|true,log|dmesg | tail -n 50"'
    h_code '"Optionnelle|true,continu|systemctl status nginx"'
    h_code '"Critique|true,stop|mount /dev/sdb1 /mnt"'
    h_vide
    h_opt "true"      "demande avant de lancer"
    h_opt "false"     "lance directement"
    h_opt ",log"      "la sortie va aussi dans le journal (pas d'interactif, un cd n'y persiste pas)"
    h_opt ",continu"  "un échec est ignoré, sans question"
    h_opt ",stop"     "un échec arrête tout, sans question"
    h_vide
    h_ligne "Pas de | dans le titre ; ceux de la commande sont libres."
    h_ligne "Le code de sortie de la commande fait ● ou ✗. Un échec sans"
    h_ligne "« continu » ni « stop » pose la question : continuer ou non."
    h_titre "Répondre à une étape"
    h_ligne "e  éditer la commande POUR CETTE FOIS : rien n'est retenu."
    h_ligne "r  oublier les [[valeurs]] de l'étape et les redemander ; la"
    h_ligne "   nouvelle réponse vaut aussi pour les étapes suivantes, et"
    h_ligne "   les {{listes}} sont relues. À faire quand on s'est trompé"
    h_ligne "   de chemin ou d'entrée, ou quand le dossier a changé."
    h_ligne "p  passer l'étape.   q  arrêter, avec le récapitulatif."

    h_titre "Les variables"
    h_ligne "\$VAR est remplacée au moment de lire les commandes ; \\\$VAR survit"
    h_ligne "jusqu'à l'exécution — c'est ce qu'il faut dans une boucle :"
    h_code "\"Boucle|true|for f in '\$DOSSIER'/*; do echo \\\$f; done\""
    h_vide
    h_ligne "Les commandes tournent dans le shell du script : vos fonctions"
    h_ligne "sont appelables, un cd persiste, set -u est actif. « exit » y"
    h_ligne "arrête le script : pour marquer un échec, rendez un code non nul."
}

aide_valeurs() {
    h_titre "Demander une valeur   [[nom]]"
    h_ligne "Demandée une fois, réutilisée par toutes les étapes qui l'écrivent."
    h_code '"Récents|true|find / -mtime -[[jours]]"'
    h_ligne "Fournie d'avance : --var jours=7   ·   la ressaisir : touche r"
    h_ligne "Le même [[nom]] dans le titre s'affiche avec la valeur, une fois"
    h_ligne "connue. TOUJOURS entre apostrophes : '[[nom]]', même collé à une"
    h_ligne "option : -o '[[offset]]' ou -mtime -'[[jours]]'. C'est ce qui rend"
    h_ligne "une valeur inoffensive quoi qu'elle contienne — un nom lu sur un"
    h_ligne "disque, par exemple. Nue, elle serait exécutée telle quelle."
    h_titre "Répéter une étape   {{nom}}"
    h_ligne "L'étape est rejouée pour chaque valeur de la liste « nom »."
    h_ex "\"Taille|true|du -sh '{{dossier}}'\"" "toujours entre apostrophes"
    h_titre "Les listes   section 4 du script"
    h_ligne "Un nom, et une commande qui écrit une valeur par ligne."
    h_code '"jours|printf '"'"'%s\n'"'"' 1 7 30"'
    h_code "\"dossier|lister_dossiers '\$DOSSIER'\""
    h_vide
    h_ligne "Même nom qu'un [[ ]] : la question devient un menu numéroté."
    h_ligne "Écrite en {{ }} : une itération par valeur, annoncées avant."
    h_titre "Les libellés   valeur<TAB>libellé"
    h_ligne "Seule la valeur entre dans la commande ; le libellé s'affiche, et"
    h_ligne "{{nom_libelle}} le rend dans la commande."
    h_ex "\"home|printf '%s\\t%s\\n' 51-144-1 alice\"" "valeur, puis libellé"
    h_titre "Listes emboîtées"
    h_ligne "Une liste peut en appeler une autre : elle est régénérée pour"
    h_ligne "chaque valeur de celle dont elle dépend, et l'étape parcourt les"
    h_ligne "deux niveaux toute seule. Une branche sans résultat ne produit"
    h_ligne "rien, sans erreur."
    h_code '"compte|lister_utilisateurs"'
    h_code '"historique|lister_si_present '"'"'{{compte}}/.bash_history'"'"'"'
    h_code '"Copie|true|cp '"'"'{{historique}}'"'"' /sauve/{{compte_libelle}}"'
    h_vide
    h_ligne "Voir ce qui sera demandé et d'où ça vient : --vars"
    h_ligne "Figer une liste sans l'interroger : --list dossier=/a,/b"
    h_ligne "Mêmes règles qu'une valeur tapée ; figée, une liste n'est plus"
    h_ligne "régénérée par celles dont elle dépendait."
}

aide_outils() {
    h_titre "Listes toutes faites   section 7 du script"
    h_ligne "Elles écrivent déjà valeur<TAB>libellé, encaissent les noms avec"
    h_ligne "espaces ou apostrophes, laissent Ctrl-C sortir, et ne prennent"
    h_ligne "jamais « rien trouvé » pour une erreur."
    h_vide
    h_opt "lister_dossiers"     "[-i] <racine> [motif...]    sous-dossiers directs"
    h_opt "lister_fichiers"     "[-i] <racine> [motif...]    fichiers directs"
    h_opt "lister_arbre"        "[-i] <racine> [motif...]    toute l'arborescence"
    h_opt "lister_recents"      "[-i] <racine> <jours> [motif...]"
    h_opt "lister_gros"         "[-i] <racine> <Mo> [motif...]"
    h_opt "lister_si_present"   "<chemin>...                 ce qui existe"
    h_opt "lister_lignes"       "[-i] <fichier> [motif...]   un fichier de valeurs"
    h_opt "lister_colonne"      "<fichier> <n> [séparateur]  la colonne n"
    h_opt "lister_utilisateurs" "[uid_mini]                  les comptes"
    h_opt "lister_montages"     "[-i] [motif...]             les disques montés"
    h_titre "Les motifs"
    h_ligne "Facultatifs et multiples. Ils portent sur le NOM seul, jamais sur"
    h_ligne "le chemin, et distinguent les majuscules ; -i les ignore."
    h_ligne "Un motif vide vaut « pas de motif » : une variable oubliée dans"
    h_ligne "un fichier -c ne fait pas disparaître la liste en silence."
    h_vide
    h_ex "lister_fichiers /etc"                  "tout, cachés compris"
    h_ex "lister_fichiers /etc '*.conf' '*.cfg'" "deux motifs"
    h_ex "lister_fichiers /etc '[!.]*'"          "sauf les cachés"
    h_ex "lister_fichiers -i /docs '*.pdf'"      "-i : .pdf, .PDF, .Pdf"
    h_titre "Écrire la vôtre"
    h_ligne "emettre <valeur> [libellé] écrit une ligne et refuse ce qui"
    h_ligne "casserait la suite. Avec le test d'interruption, c'est tout."
    h_code "ma_liste() {"
    h_code "    local d"
    h_code "    for d in \"\$1\"/*/; do"
    h_code "        (( INTERROMPU )) && return 130"
    h_code "        emettre \"\${d%/}\" \"\$(basename \"\$d\")\""
    h_code "    done"
    h_code "    return 0"
    h_code "}"
    h_vide
    h_ligne "Valeurs sur la sortie standard, messages sur >&2 : ils vont au"
    h_ligne "journal. Une liste vide n'est pas une erreur."
}

aide_config() {
    h_titre "Le fichier -c"
    h_ligne "Un nom en TK_ appartient au script : à remplir, jamais à supprimer"
    h_ligne "ni à renommer. Un nom en _ est un rouage : le script s'en sert"
    h_ligne "entre deux étapes. Le reste des noms est à vous."
    h_vide
    h_ligne "Du shell, chargé après le script : il peut fixer les variables et"
    h_ligne "redéfinir les trois fonctions. Un squelette prêt à remplir :"
    h_code "./$NOM_SCRIPT -t > mon-cas.conf"
    h_code "./$NOM_SCRIPT -c mon-cas.conf"
    h_vide
    h_ligne "Priorité : valeurs du script < fichier -c < --set."
    h_ligne "Dans le fichier : return, jamais exit."
    h_titre "Les trois fonctions   sections 3, 4 et 6 du script"
    h_opt "calculer_variables" "appelée après -c et --set ; pose les noms ci-dessous"
    h_opt "verifier"           "contrôles de départ ; return 1 pour arrêter"
    h_opt "definir_commandes"  "remplit TK_COMMANDES et TK_LISTES"
    h_titre "Les noms que le script lit   tout ce qui commence par TK_"
    h_ligne "Vos commandes tournent dans le shell du script : un « NUM=1 » chez"
    h_ligne "vous ne peut rien casser chez lui, ses noms à lui sont en _."
    h_opt "TK_SUJET"    "titre court, en tête et au récapitulatif"
    h_opt "TK_DETAILS"  "lignes du bandeau, « clé=valeur » (clé sans accent)"
    h_opt "TK_PREFIX"   "préfixe des fichiers écrits"
    h_opt "TK_DIR_LOGS" "journal, rapport, état de reprise ; tout TK_DIR_xxx est créé"
    h_opt "TK_INTRO"    "texte affiché après le bandeau (facultatif)"
    h_titre "Les réglages   section 2"
    h_opt "TK_REQUIS"         "binaires attendus, absents = avertissement : (du df)"
    h_opt "TK_OPERATEUR"      "qui a lancé ; \${SUDO_USER:-\$USER} sous sudo"
    h_opt "TK_TOUT_VALIDER"   "true = confirmer chaque étape, même les « false »"
    h_opt "TK_MAX_ITERATIONS" "plafond d'une étape répétée, au-delà elle est tronquée"
}

aide_exemple() {
    h_titre "Un cas complet   à copier dans un fichier, puis -c ce fichier"
    h_vide
    h_code "# Sauvegarde des comptes d'une machine."
    h_code "RACINE=\"/sauve/\$(hostname)\"        # ce qui change d'un usage à l'autre"
    h_code "TK_REQUIS=(tar du)"
    h_code ""
    h_code "calculer_variables() {"
    h_code "    TK_SUJET=\"sauvegarde \$(hostname)\""
    h_code "    TK_DETAILS=(\"racine=\$RACINE\")"
    h_code "    TK_PREFIX=\"sauve\""
    h_code "    TK_DIR_OUT=\"\$RACINE\"              # créé au besoin"
    h_code "    TK_DIR_LOGS=\"\$RACINE/logs\""
    h_code "}"
    h_code ""
    h_code "verifier() { [[ -w /sauve ]] || { erreur \"/sauve non inscriptible\"; return 1; }; }"
    h_code ""
    h_code "definir_commandes() {"
    h_code "TK_COMMANDES=("
    h_code "\"Place disponible|false|df -h /sauve\""
    h_code "\"Taille de chaque compte|false|du -sh '{{compte}}'\""
    h_code "\"Archive de chaque compte|true,log|tar czf '\$TK_DIR_OUT/{{compte_libelle}}.tgz' '{{compte}}'\""
    h_code "\"Purge des archives anciennes|true|find '\$TK_DIR_OUT' -name '*.tgz' -mtime +[[jours]] -delete\""
    h_code ")"
    h_code "TK_LISTES=("
    h_code "\"compte|lister_utilisateurs\""
    h_code "\"jours|printf '%s\\t%s\\n' 30 'un mois' 90 'un trimestre'\""
    h_code ")"
    h_code "}"
    h_vide
    h_ligne "Ce que ça donne : quatre étapes, la 2 et la 3 rejouées par compte,"
    h_ligne "un menu à deux entrées pour [[jours]]. Voir avant de lancer : -l"
    h_ligne "puis --vars ; répéter sans question : -y --var jours=30."
}

aide_sujet() {
    case "${1,,}" in
        etapes|étapes|etape|step)  aide_etapes ;;
        valeurs|valeur|listes|liste) aide_valeurs ;;
        outils|outil|fonctions)    aide_outils ;;
        config|conf|fichier)       aide_config ;;
        exemple|exemples|demo)     aide_exemple ;;
        tout|all)                  aide_etapes; h_vide; aide_valeurs; h_vide
                                   aide_outils; h_vide; aide_config; h_vide; aide_exemple ;;
        *) erreur "aide : sujet inconnu « $1 »"
           info "sujets : $SUJETS"; return 1 ;;
    esac
    printf '\n'
    return 0
}

aide() {
    printf '%s%s%s — enchaîne des commandes, validées une à une.\n' "$GRAS" "$NOM_SCRIPT" "$C0"
    printf 'Usage : %s./%s%s [options]\n' "$C_PROG" "$NOM_SCRIPT" "$C0"
    h_titre "Configurer"
    h_opt "-c, --config FICHIER" "variables lues dans un fichier"
    h_opt "-t, --template"       "écrire un fichier -c prêt à compléter (sur la sortie standard)"
    h_opt "-s, --set NOM=valeur" "fixer une variable des sections 1 et 2"
    h_opt "-D, --var nom=valeur" "répondre d'avance à une question [[nom]]"
    h_opt "    --list nom=a,b"   "figer une liste {{nom}}"
    h_opt "    --vars"           "montrer les questions et listes attendues"
    h_titre "Choisir les étapes"
    h_opt "-l, --plan"           "montrer le plan, sans rien lancer"
    h_opt "-n, --dry-run"        "tout afficher, ne rien exécuter"
    h_opt "-o, --only 2,5-7"     "ne jouer que ces étapes"
    h_opt "-f, --from 4"         "partir de l'étape 4"
    h_opt "-r, --resume"         "sauter les étapes déjà réussies"
    h_titre "Dialoguer"
    h_opt "-a, --ask"            "confirmer chaque étape, même les « false »"
    h_opt "-y, --yes"            "ne rien demander (sudo ? faites « sudo -v » avant)"
    h_opt "    --color MODE"     "auto, always ou never  ·  --no-color"
    h_opt "-h, --help [SUJET]"      "cette aide ; SUJET = un chapitre, voir plus bas"
    h_titre "Pendant l'exécution"
    h_cle "à une étape"     "Entrée=exécuter" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"
    h_cle "étape répétée"   "u=une par une" "l=lister les itérations"
    h_cle "question posée"  "1 2 3=choisir" "a=autre valeur" "p=passer" "q=quitter"
    h_cle "Ctrl-C"          "=interrompt la commande ; à une question, arrête le script"
    printf '  %-16s %s à faire  %s en cours  %s réussie  %s échec  %s passée  %s interrompue  %s simulée\n' "marques" \
           "${GLYPHE[todo]}" "${GLYPHE[cours]}" "${GLYPHE[ok]}" "${GLYPHE[ko]}" "${GLYPHE[skip]}" "${GLYPHE[int]}" "${GLYPHE[sim]}"
    h_titre "Dans le script   1 variables · 2 réglages · 3 commandes · 4 listes · 5 fonctions"
    printf '  %s"Titre|true|commande"%s   true = demander avant, false = lancer direct\n' "$C_PROG" "$C0"
    printf '  %s[[nom]]%s  une valeur demandée une fois       %s{{nom}}%s  l%sétape rejouée par valeur\n' "$C_PROG" "$C0" "$C_PROG" "$C0" "'"
    h_titre "En savoir plus   -h SUJET"
    h_opt "-h etapes"   "la ligne « Titre|validation|commande », les variables"
    h_opt "-h valeurs"  "[[demandée]], {{répétée}}, menus, libellés, emboîtement"
    h_opt "-h outils"   "les dix listes toutes faites, et écrire la vôtre"
    h_opt "-h config"   "le fichier -c, les noms que le script lit"
    h_opt "-h exemple"  "un cas complet, à copier"
    h_opt "-h tout"     "les cinq d'affilée"
    printf '\n  Code de sortie : 1 s%sil reste un échec\n\n' "'"
}

# ---------- --template : un fichier -c déduit des sections 1 et 2 ----------
# On relit ces sections de ce fichier même : si vous y ajoutez ou renommez
# une variable, le gabarit suit. La valeur écrite est la valeur courante,
# donc « -c pc07.conf --template » donne un gabarit pré-rempli.
gabarit() {
    local src="${BASH_SOURCE[0]}" ligne nom com val decl e
    local -A deja=()
    printf '# Fichier de configuration pour %s — généré par --template\n' "$NOM_SCRIPT"
    printf '#     ./%s -c CE_FICHIER\n#\n' "$NOM_SCRIPT"
    printf '# Du shell : les guillemets sont obligatoires dès qu%sil y a un espace.\n' "'"
    printf '# On peut aussi y redéfinir calculer_variables, verifier ou\n'
    printf '# definir_commandes : voir exemples/.\n\n'
    # Généré depuis un fichier -c : on en hérite, et ce sont SES variables
    # qui sont proposées — celles du script ne le concernent pas.
    if [[ -n "$_CONF" ]]; then
        printf 'source "%s"\n\n' "$(readlink -f "$_CONF" 2>/dev/null || printf '%s' "$_CONF")"
    fi
    while IFS= read -r ligne; do
        [[ "$ligne" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        nom="${BASH_REMATCH[1]}"; com=""
        [[ "${BASH_REMATCH[2]}" =~ \#[[:space:]]*(.*)$ ]] && com="${BASH_REMATCH[1]}"
        decl="$(declare -p "$nom" 2>/dev/null)" || continue
        if [[ "$decl" == "declare -a"* ]]; then
            local -n _t="$nom"; val=""
            for e in ${_t[@]+"${_t[@]}"}; do val+="${val:+ }$(printf '%q' "$e")"; done
            val="($val)"
        else
            val="${!nom}"
            val="${val//\\/\\\\}"; val="${val//\"/\\\"}"; val="${val//\$/\\\$}"; val="${val//\`/\\\`}"
            val="\"$val\""
        fi
        [[ -z "${deja[$nom]:-}" ]] || continue; deja[$nom]=1
        if [[ -n "$com" ]]; then printf '%-30s # %s\n' "$nom=$val" "$com"; else printf '%s=%s\n' "$nom" "$val"; fi
    done < <(if [[ -n "$_CONF" ]]; then sed '/^[a-zA-Z_][a-zA-Z0-9_]*() *{/,$d' "$_CONF" | grep -E '^[A-Za-z_][A-Za-z0-9_]*='
             else sed -n '/^# 1\. VARIABLES/,/^# 3\./p' "$src"; fi)
    (( ${#deja[@]} > 0 )) || erreur "aucune variable trouvée ${_CONF:+dans $_CONF}${_CONF:-entre les bandeaux « # 1. » et « # 3. » de $src}"
}


# --- 8.3 Arguments et configuration ----------------------------------
PRESETS=(); PRESETS_LISTE=(); SETS=()
_CONF=""; TK_INTRO=""
_LISTER_VARS="false"; _LISTER_ETAPES="false"; _SIMULATION="false"; _AIDE="false"; _GABARIT="false"
SUJET_AIDE=""
_SANS_QUESTION="false"; _REPRENDRE="false"; _FILTRE_ETAPES=""; _DEPUIS=0

exige_valeur() { [[ -n "${2:-}" ]] || { printf '✗  %s attend une valeur.\n' "$1" >&2; exit 1; }; }

# Options courtes à la manière de getopt : -yn vaut -y -n, -o3 vaut -o 3,
# -cFICHIER vaut -c FICHIER.
ARGS=()
for a in "$@"; do
    if [[ "$a" =~ ^-[a-zA-Z].+$ ]]; then
        reste="${a#-}"
        while [[ -n "$reste" ]]; do
            l="${reste:0:1}"; reste="${reste:1}"
            case "$l" in
                c|s|D|o|f) ARGS+=("-$l"); [[ -n "$reste" ]] && ARGS+=("$reste"); reste="" ;;
                *)         ARGS+=("-$l") ;;
            esac
        done
    else ARGS+=("$a"); fi
done
set -- ${ARGS[@]+"${ARGS[@]}"}

while (( $# > 0 )); do
    case "$1" in
        -a|--ask)          TK_TOUT_VALIDER="true";  shift ;;
        -y|--yes)          _SANS_QUESTION="true"; shift ;;
        -n|--dry-run)      _SIMULATION="true";    shift ;;
        -l|--plan)         _LISTER_ETAPES="true"; shift ;;
        -r|--resume)       _REPRENDRE="true";     shift ;;
        --vars)            _LISTER_VARS="true";   shift ;;
        --no-color)        _COULEUR="non";        shift ;;
        -D|--var)          exige_valeur "$1" "${2:-}"; PRESETS+=("$2");       shift 2 ;;
        --var=*)           PRESETS+=("${1#*=}");                              shift ;;
        --list)            exige_valeur "$1" "${2:-}"; PRESETS_LISTE+=("$2"); shift 2 ;;
        --list=*)          PRESETS_LISTE+=("${1#*=}");                        shift ;;
        -s|--set)          exige_valeur "$1" "${2:-}"; SETS+=("$2");          shift 2 ;;
        --set=*)           SETS+=("${1#*=}");                                 shift ;;
        -o|--only)         exige_valeur "$1" "${2:-}"; _FILTRE_ETAPES="$2";    shift 2 ;;
        --only=*)          _FILTRE_ETAPES="${1#*=}";                           shift ;;
        -f|--from)         exige_valeur "$1" "${2:-}"; _DEPUIS="$2";           shift 2 ;;
        --from=*)          _DEPUIS="${1#*=}";                                  shift ;;
        -c|--config)       exige_valeur "$1" "${2:-}"; _CONF="$2";             shift 2 ;;
        --config=*)        _CONF="${1#*=}";                                    shift ;;
        --color)           exige_valeur "$1" "${2:-}"; _COULEUR="$2";          shift 2 ;;
        --color=*)         _COULEUR="${1#*=}";                                 shift ;;
        -t|--template)     _GABARIT="true";       shift ;;
        -h|--help)         _AIDE="true"
                           # « -h listes » : le mot qui suit est un sujet,
                           # sauf si c'est une autre option.
                           if [[ -n "${2-}" && "$2" != -* ]]; then SUJET_AIDE="$2"; shift; fi
                           shift ;;
        --help=*)          _AIDE="true"; SUJET_AIDE="${1#*=}";                     shift ;;
        -*) printf '✗  option inconnue : %s   (-h pour l'"'"'aide)\n' "$1" >&2; exit 1 ;;
        *)  printf '✗  argument inattendu : %s   (tout passe par des options, -h pour l'"'"'aide)\n' "$1" >&2; exit 1 ;;
    esac
done
case "$_COULEUR" in always|yes|oui) _COULEUR="oui" ;; never|no|non) _COULEUR="non" ;; auto) ;;
    *) printf -- '✗  --color attend auto, always ou never.\n' >&2; exit 1 ;; esac
init_affichage
if [[ "$_AIDE" == "true" ]]; then
    if [[ -n "$SUJET_AIDE" ]]; then aide_sujet "$SUJET_AIDE"; exit $?; fi
    aide; exit 0
fi

# Le fichier -c est du shell : il peut fixer les variables, mais aussi
# redéfinir definir_commandes et ajouter des fonctions (voir exemples/).
if [[ -n "$_CONF" ]]; then
    [[ -e "$_CONF" ]] || { erreur "configuration introuvable : $_CONF"; exit 1; }
    [[ -f "$_CONF" ]] || { erreur "configuration : pas un fichier : $_CONF"; exit 1; }
    [[ -r "$_CONF" ]] || { erreur "configuration illisible : $_CONF"; exit 1; }
    if ! bash -n "$_CONF" 2>/dev/null; then
        erreur "erreur de syntaxe dans $_CONF"
        # Un fichier écrit sous Windows finit ses lignes par CR : bash le
        # signale comme une fin de fichier inattendue, ce qui n'aide personne.
        grep -q $'\r' "$_CONF" 2>/dev/null && info "le fichier contient des retours chariot (Windows) : dos2unix ou sed -i 's/\r\$//'"
        bash -n "$_CONF"; exit 1
    fi
    # Un « exit » dans le fichier tuerait le script sans un mot : on le
    # charge d'abord dans un sous-shell pour le voir venir.
    # shellcheck disable=SC1090
    ( source "$_CONF" >/dev/null 2>&1 ) || { erreur "$_CONF s'est terminé tout seul (code $?) : un « exit » dedans ? Utilisez return."; exit 1; }
    # shellcheck disable=SC1090
    source "$_CONF" || { erreur "échec du chargement de $_CONF"; exit 1; }
fi
# --set NOM=valeur : n'importe quelle variable des sections 1 et 2. On exige
# qu'elle existe déjà, sinon une faute de frappe passerait inaperçue.
for e in ${SETS[@]+"${SETS[@]}"}; do
    k="${e%%=*}"
    [[ "$e" == *=* && "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { erreur "--set attend NOM=valeur : $e"; exit 1; }
    decl="$(declare -p "$k" 2>/dev/null)" || { erreur "--set : aucune variable « $k » en section 1 ni 2"; exit 1; }
    [[ "$decl" != "declare -a"* && "$decl" != "declare -A"* ]] || { erreur "--set : « $k » est un tableau, modifiez-le dans le fichier -c"; exit 1; }
    printf -v "$k" '%s' "${e#*=}" 2>/dev/null \
        || { erreur "--set : « $k » ne peut pas être modifiée (lecture seule ?)"; exit 1; }
done
case "${TK_TOUT_VALIDER,,}" in true|oui|1) TK_TOUT_VALIDER="true" ;; *) TK_TOUT_VALIDER="false" ;; esac
[[ "$TK_MAX_ITERATIONS" =~ ^[0-9]+$ ]] && (( TK_MAX_ITERATIONS >= 1 )) \
    || { erreur "TK_MAX_ITERATIONS doit être un entier positif : $TK_MAX_ITERATIONS"; exit 1; }
[[ "$_DEPUIS" =~ ^[0-9]+$ ]] || { erreur "--from attend un numéro d'étape"; exit 1; }
_DEPUIS=$(( 10#$_DEPUIS ))
_FILTRE_ETAPES="${_FILTRE_ETAPES//[[:space:]]/}"
if [[ -n "$_FILTRE_ETAPES" ]]; then
    IFS=, read -r -a _morceaux <<< "$_FILTRE_ETAPES"
    for m in "${_morceaux[@]}"; do
        [[ "$m" =~ ^[0-9]+(-[0-9]+)?$ ]] || { erreur "--only : « $m » n'est ni un numéro ni un intervalle"; exit 1; }
        [[ "$m" != *-* ]] || (( 10#${m%-*} <= 10#${m#*-} )) || { erreur "--only : intervalle inversé « $m »"; exit 1; }
    done
fi

calculer_variables
# Sans ces trois-là, la mécanique casserait bien plus loin, sur une
# variable non définie, à un endroit qui n'aiderait personne. Le cas se
# produit dès qu'un fichier -c redéfinit calculer_variables.
for v in TK_SUJET TK_PREFIX TK_DIR_LOGS; do
    [[ -n "${!v:-}" ]] || { erreur "calculer_variables doit définir $v (section 6, ou votre fichier -c)"; exit 1; }
done
[[ "$TK_PREFIX" != */* ]] || { erreur "TK_PREFIX ne peut pas contenir de / : $TK_PREFIX"; exit 1; }

[[ "$_GABARIT" == "true" ]] && { gabarit; exit 0; }

# Un fichier -c peut écrire TK_COMMANDES et TK_LISTES directement, sans passer
# par definir_commandes : on les prend tels quels. Sinon on appelle la
# fonction — d'abord dans un sous-shell, pour transformer un
# « TK_DIR_BODY: unbound variable » en explication.
if ! declare -p TK_COMMANDES >/dev/null 2>&1; then
    if ! _err="$( (definir_commandes) 2>&1 )"; then
        erreur "impossible de construire TK_COMMANDES : ${_err##*: }"
        info "une variable utilisée en section 3 ou 4 n'existe pas — votre fichier -c redéfinit calculer_variables sans definir_commandes ?"
        exit 1
    fi
    # Des tableaux vides d'abord : une definir_commandes qui ne remplit rien
    # sortait un « TK_COMMANDES: unbound variable » au lieu du message d'à côté.
    TK_COMMANDES=(); TK_LISTES=()
    definir_commandes
fi
declare -p TK_LISTES >/dev/null 2>&1 || TK_LISTES=()
_TOTAL=${#TK_COMMANDES[@]}
_LARG_NUM=${#_TOTAL}; (( _LARG_NUM < 2 )) && _LARG_NUM=2


# --- 8.4 Saisies et signaux ------------------------------------------
# Les questions se lisent sur /dev/tty : l'entrée standard peut être
# prise par une commande.
if (exec 3< /dev/tty) 2>/dev/null; then _ENTREE="/dev/tty"; _INTERACTIF="oui"
else _ENTREE="/dev/stdin"; _INTERACTIF="non"; fi

_LOG="/dev/null"
journal() { printf '[%(%F %T)T] %s\n' -1 "$*" >> "$_LOG"; }

# Une commande peut laisser le terminal inutilisable : un programme plein
# écran interrompu par Ctrl-C au mauvais moment ne rend pas la main
# proprement — les touches ne s'affichent plus, Entrée ne
# valide plus. On mémorise les réglages et on les remet après chaque
# commande, ainsi qu'en sortant.
TTY_ETAT=""
[[ -r /dev/tty ]] && TTY_ETAT="$(stty -g 2>/dev/null < /dev/tty)" 2>/dev/null
# Régler le terminal depuis un job en arrière-plan (./tasker.sh -y &)
# vaudrait un SIGTTOU : le script serait stoppé net. On ne le fait que si
# l'on est au premier plan.
en_avant_plan() {
    local stat t p
    # /proc d'abord : c'est deux forks de ps en moins après chaque commande.
    # Le nom du processus, entre parenthèses, peut contenir des espaces :
    # on lit après la dernière. Champs : état ppid pgrp session tty tpgid.
    if [[ -r /proc/$$/stat ]] && read -r stat < /proc/$$/stat; then
        stat="${stat##*) }"; read -r _ _ p _ _ t _ <<< "$stat"
    else
        t="$(ps -o tpgid= -p $$ 2>/dev/null)"; p="$(ps -o pgid= -p $$ 2>/dev/null)"
    fi
    [[ -n "${t// /}" && "${t// /}" == "${p// /}" ]]
}
restaurer_terminal() {
    [[ -n "$TTY_ETAT" ]] && en_avant_plan && { stty "$TTY_ETAT" < /dev/tty; } 2>/dev/null
    return 0
}

# Les commandes s'exécutent DANS ce shell (c'est ce qui permet d'appeler
# vos fonctions). Une commande qui fait « set -e », change IFS ou retire
# un trap casserait donc la suite : après chaque commande, on remet ce
# dont la mécanique dépend.
SHOPT_TK="$(shopt -p)"       # les options du shell au départ, remises après chaque commande
SET_TK="$(set +o)"           # idem pour set : un « set -f » dans une étape éteignait toutes les listes d'après
# Une commande tourne dans ce shell : un « exec 1>&- » ou un « exec
# 2>/tmp/x » emporterait la sortie du script avec elle, jusqu'au
# récapitulatif. On garde une copie des deux descripteurs, remise après
# chaque commande.
exec {FD_SORTIE}>&1 {FD_ERREUR}>&2
retablir_shell() {
    exec 1>&"$FD_SORTIE" 2>&"$FD_ERREUR"
    eval "$SET_TK"
    IFS=$' \t\n'
    eval "$SHOPT_TK"
    if [[ "$LC_ALL_TK" == "__absent__" ]]; then unset LC_ALL; else LC_ALL="$LC_ALL_TK"; fi
    trap gerer_int INT
    trap au_revoir EXIT
    trap 'journal "ARRÊT : SIGHUP (terminal fermé)"; exit 129' HUP
    trap 'journal "ARRÊT : SIGTERM"; exit 143' TERM
    restaurer_terminal
}

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
# Terminal fermé ou kill : on passe par exit pour que le trap EXIT écrive
# le récapitulatif et le rapport, et que le journal dise pourquoi.
trap 'journal "ARRÊT : SIGHUP (terminal fermé)"; exit 129' HUP
trap 'journal "ARRÊT : SIGTERM"; exit 143' TERM

# lire <invite> <variable> : Entrée vide = défaut ; Ctrl-D = arrêt.
lire() {
    local rc
    [[ "$_SANS_QUESTION" == "true" ]] && { printf -v "$2" '%s' ""; return 0; }
    EN_SAISIE=1
    # shellcheck disable=SC2229
    read -r -p "$1" "$2" < "$_ENTREE"; rc=$?
    EN_SAISIE=0
    if (( rc != 0 )); then
        printf '\n'; erreur "fin de l'entrée clavier (Ctrl-D) — arrêt."
        journal "ARRÊT : fin de l'entrée clavier"; exit 130
    fi
    return 0
}
lire_edit() {   # <valeur initiale> <variable>
    EN_SAISIE=1
    read -r -e -i "$1" -p "  ${CYAN}\$${C0} " "$2" < "$_ENTREE" || true
    EN_SAISIE=0
}
demander_oui_non() {   # vrai sauf n / q
    local r=""; lire "$1" r
    case "${r,,}" in n|non|q) return 1 ;; *) return 0 ;; esac
}
quitter() {   # [code] — sans argument : 1 s'il y a déjà eu un échec
    printf '\n'; info "arrêt demandé."; journal "ARRÊT demandé"
    exit "${1:-$(( _NB_KO > 0 ))}"
}


# --- 8.5 Valeurs, listes, emboîtement --------------------------------
RE_SIMPLE='\[\[([a-zA-Z0-9_]+)\]\]'
RE_LISTE='\{\{([a-zA-Z0-9_]+)\}\}'

# =() est obligatoire : sous set -u, un « declare -A X » nu rend ${#X[@]} illégal.
declare -A _REPONSES=()      # [[nom]] -> valeur
declare -A GENERATEUR=()    # liste   -> commande
declare -A CACHE_LISTE=()   # commande résolue -> lignes
declare -A CACHE_CODE=()    # commande résolue -> code quand elle n'a rien rendu
declare -A LISTE_FIGEE=()   # --list nom=a,b
declare -A BINDINGS=()      # {{nom}} liés dans la boucle en cours (échappés)
PH_SIMPLES=(); USAGE_SIMPLES=(); PH_LISTES=(); USAGE_LISTES=()
_ETAPE_PASSEE=0              # mis à 1 quand l'utilisateur répond « p » à une question

echapper_apostrophes() { printf '%s' "${1//\'/\'\\\'\'}"; }

charger_listes() {
    local e nom
    for e in ${TK_LISTES[@]+"${TK_LISTES[@]}"}; do
        nom="${e%%|*}"
        [[ "$e" == *"|"* && -n "${e#*|}" ]] || { erreur "TK_LISTES : il faut nom|commande : $e"; exit 1; }
        [[ "$nom" =~ ^[a-zA-Z0-9_]+$ && "$nom" != *_libelle ]] || { erreur "TK_LISTES : nom invalide « $nom »"; exit 1; }
        [[ -z "${GENERATEUR[$nom]:-}" ]] || { erreur "TK_LISTES : « $nom » défini deux fois"; exit 1; }
        GENERATEUR["$nom"]="${e#*|}"
    done
}

substituer_liaisons() {   # remplace les {{nom}} déjà liés
    local t="$1" k
    if (( ${#BINDINGS[@]} > 0 )); then
        for k in "${!BINDINGS[@]}"; do remplacer "$t" "{{$k}}" "${BINDINGS[$k]}"; t="$REMPLACE"; done
    fi
    printf '%s' "$t"
}

liste_de() {   # {{home_libelle}} désigne la liste « home »
    local n="$1"
    [[ -z "${GENERATEUR[$n]:-}${LISTE_FIGEE[$n]:-}" && "$n" == *_libelle ]] && n="${n%_libelle}"
    printf '%s' "$n"
}

valeur_valide() {
    [[ -n "$1" ]] || { printf '    %svaleur vide refusée%s\n' "$C_WARN" "$C0"; return 1; }
    [[ "$1" != *$'\n'* ]] || { printf '    %sune valeur tient sur une ligne%s\n' "$C_WARN" "$C0"; return 1; }
    [[ "$1" != *'[['* && "$1" != *'{{'* ]] || { printf '    %s[[ et {{ sont interdits dans une valeur%s\n' "$C_WARN" "$C0"; return 1; }
    return 0
}

etapes_mot() {   # « aux étapes 2, 3 » / « à l'étape 2 » / « seulement par la liste v »
    if [[ "$1" == et\ * ]]; then printf 'seulement'; elif [[ "$1" == *,* ]]; then printf 'aux étapes'; else printf "à l'étape"; fi; }
sans_et()    { printf '%s' "${1#et }"; }
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
    # code_vide est local : sans cela, la liste vide d'à côté héritait du
    # code d'une autre, et le message annonçait une erreur jamais produite.
    local nom="$1" gen sortie rc ligne val lib code_vide=0

    if [[ -n "${LISTE_FIGEE[$nom]:-}" ]]; then
        VALEURS=(); LIBELLES=()
        while IFS= read -r ligne; do [[ -n "$ligne" ]] && { VALEURS+=("$ligne"); LIBELLES+=(""); }; done <<< "${LISTE_FIGEE[$nom]}"
        return 0
    fi
    [[ -n "${GENERATEUR[$nom]:-}" ]] || {
        erreur "aucune liste « $nom » en section 4 (voir --vars)"
        info "si {{$nom}} n'était pas censé être une liste, doublez l'accolade autrement"
        return 1; }

    resoudre_simples "${GENERATEUR[$nom]}" || return 1
    gen="$(substituer_liaisons "$_CMD")"
    if [[ "$gen" =~ $RE_LISTE ]]; then
        erreur "la liste « $nom » dépend de {{${BASH_REMATCH[1]}}} : elle ne peut pas servir ici"; return 1
    fi

    if [[ -n "${CACHE_LISTE[$gen]:-}" ]]; then
        sortie="${CACHE_LISTE[$gen]}"; [[ "$sortie" == $'\001' ]] && sortie=""
        code_vide="${CACHE_CODE[$gen]:-0}"
    else
        journal "LISTE $nom : $gen"
        [[ -t 1 ]] && printf '  %s… lecture de la liste « %s »%s' "$ESTOMPE" "$nom" "$C0"
        # </dev/null : une commande de liste qui lit l'entrée standard par
        # accident (cat sans argument) resterait bloquée sans rien dire.
        # sudo, lui, lit /dev/tty et n'est pas gêné.
        sortie="$(eval "$gen" 2>> "$_LOG" </dev/null)"; rc=$?
        retablir_shell
        [[ -t 1 ]] && { repeter ' ' $(( ${#nom} + 30 )); printf '\r%s\r' "$REPET"; }
        # Un code non nul sans aucune sortie n'est pas une erreur : ls, grep
        # ou find rendent justement 1 ou 2 quand ils ne trouvent rien. C'est
        # une liste vide — la branche ne produit rien — et le journal garde
        # le code pour qui veut comprendre.
        # Interrompue : ce qu'on a lu est tronqué, on ne le garde pas — la
        # prochaine étape qui lit cette liste la relira en entier.
        (( INTERROMPU )) && return 130
        if (( rc != 0 && ${#sortie} == 0 )); then journal "LISTE $nom : aucune valeur (code $rc)"; code_vide=$rc; fi
        CACHE_LISTE["$gen"]="${sortie:-$'\001'}"; CACHE_CODE["$gen"]="$code_vide"
    fi

    # Remise à zéro ICI : la résolution ci-dessus a pu rappeler generer_liste.
    VALEURS=(); LIBELLES=()
    while IFS= read -r ligne; do
        ligne="${ligne%$'\r'}"           # fins de ligne Windows
        [[ -n "$ligne" ]] || continue
        val="${ligne%%$'\t'*}"; lib=""; [[ "$ligne" == *$'\t'* ]] && lib="${ligne#*$'\t'}"
        if [[ "$val" == *'[['* || "$val" == *'{{'* ]]; then attention "valeur ignorée dans « $nom » : $val"; continue; fi
        VALEURS+=("$val"); LIBELLES+=("$lib")
    done <<< "$sortie"
    (( ${#VALEURS[@]} > 0 )) || { journal "LISTE $nom : aucune valeur"; CODE_LISTE_VIDE=$code_vide; return 2; }
    return 0
}
CODE_LISTE_VIDE=0

# demander_valeur <nom> -> _VALEUR ; 1 si l'utilisateur passe l'étape.
_VALEUR=""
demander_valeur() {
    local nom="$1" i n choix ou libre=0 ecart
    local -a v=() l=()

    if [[ -n "${GENERATEUR[$nom]:-}${LISTE_FIGEE[$nom]:-}" ]]; then
        generer_liste "$nom"
        case $? in
            0) v=("${VALEURS[@]}"); l=("${LIBELLES[@]}") ;;
            2) attention "la liste « $nom » n'a rien renvoyé$( (( CODE_LISTE_VIDE )) && printf ' (code %d)' "$CODE_LISTE_VIDE") — saisissez la valeur" ;;
        esac
    fi
    INTERROMPU=0
    ou="$(ou_sert "$nom")"; n=${#v[@]}

    printf '\n    %s┌─%s %s[[%s]]%s%s%s\n' "$C_BOITE" "$C0" "$C_PROG" "$nom" "$C0" "$ESTOMPE" "${ou:+  — utilisé $(etapes_mot "$ou") $(sans_et "$ou")}"
    if (( n > 0 )); then
        printf '    %s│%s\n' "$C_BOITE" "$C0"
        for i in "${!v[@]}"; do
            printf '    %s│%s  %s%2d%s  %s%s%s' "$C_BOITE" "$C0" "$C_CLE" $(( i + 1 )) "$C0" "$GRAS$C_OK" "${v[$i]}" "$C0"
            # La valeur est ce qui sert à choisir : elle reste entière et
            # c'est le libellé qui est coupé s'il ne reste plus la place.
            if [[ -n "${l[$i]}" ]]; then
                largeur_texte "${v[$i]}"; ecart=$(( 14 - LARG_TXT )); (( ecart < 0 )) && ecart=0
                couper "${l[$i]}" $(( _LARGEUR - 13 - LARG_TXT - ecart ))
                printf '%*s  %s%s%s' "$ecart" '' "$ESTOMPE" "$COUPE" "$C0"
            fi
            printf '\n'
        done
        printf '    %s│%s\n' "$C_BOITE" "$C0"
        if [[ "$_SANS_QUESTION" != "true" ]]; then
            printf '    %s│%s  %s a%s  %ssaisir une autre valeur%s\n' "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
            printf '    %s│%s  %s p%s  %spasser cette étape%s\n'       "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
            printf '    %s│%s  %s q%s  %squitter le script%s\n'        "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
        fi
        while true; do
            choix=""; lire "    $C_BOITE└─$C0 votre choix ${ESTOMPE}[1]${C0} ${GRAS}›${C0} " choix
            [[ -z "$choix" ]] && choix=1
            case "${choix,,}" in
                a) libre=1; break ;;
                p) _ETAPE_PASSEE=1; printf '    %sétape passée%s\n' "$ESTOMPE" "$C0"; return 1 ;;
                q) quitter ;;
            esac
            if [[ "$choix" =~ ^[0-9]+$ ]] && (( 10#$choix >= 1 && 10#$choix <= n )); then
                choix=$(( 10#$choix ))
                _VALEUR="${v[$(( choix - 1 ))]}"
                printf '    %s→ %s%s\n\n' "$C_OK" "${v[$(( choix - 1 ))]}" "$C0"; return 0
            fi
            printf '    %s« %s » n'"'"'est pas dans la liste%s\n' "$C_WARN" "$choix" "$C0"
        done
    else
        printf '    %s│%s  %sla valeur sera réutilisée partout où [[%s]] apparaît%s\n' "$C_BOITE" "$C0" "$ESTOMPE" "$nom" "$C0"
        printf '    %s│%s  %s p%s  %spasser cette étape%s   %s q%s  %squitter%s\n' "$C_BOITE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
    fi

    if [[ "$_SANS_QUESTION" == "true" ]]; then
        erreur "[[$nom]] n'a pas de valeur et -y interdit de la demander : --var $nom=…"; exit 1
    fi
    # Après « a », p et q sont des valeurs comme les autres.
    _VALEUR=""
    while true; do
        lire "    $C_BOITE└─$C0 valeur ${GRAS}›${C0} " _VALEUR
        if (( ! libre )); then
            case "${_VALEUR,,}" in
                p) _ETAPE_PASSEE=1; printf '    %sétape passée%s\n' "$ESTOMPE" "$C0"; return 1 ;;
                q) quitter ;;
            esac
        fi
        valeur_valide "$_VALEUR" && break
    done
    printf '\n'; return 0
}

# resoudre_simples <commande> -> _CMD ; 1 si l'utilisateur passe l'étape.
# Résultat dans une variable et non $(...) : un sous-shell perdrait _REPONSES.
_CMD=""
resoudre_simples() {
    local cmd="$1" nom
    while [[ "$cmd" =~ $RE_SIMPLE ]]; do
        nom="${BASH_REMATCH[1]}"
        if [[ -z "${_REPONSES[$nom]:-}" ]]; then
            demander_valeur "$nom" || return 1
            _REPONSES["$nom"]="$_VALEUR"
        fi
        # En mémoire la valeur est brute — c'est elle qu'on affiche ; les
        # apostrophes ne sont neutralisées qu'en entrant dans la commande.
        remplacer "$cmd" "[[$nom]]" "$(echapper_apostrophes "${_REPONSES[$nom]}")"; cmd="$REMPLACE"
    done
    _CMD="$cmd"
}

# oublier_valeurs <commande brute> : les [[valeurs]] de cette étape, y
# compris celles des listes qu'elle appelle, et le cache des listes.
oublier_valeurs() {
    local i=0 courant nom vus=" "
    local -a afaire=("$1")
    while (( i < ${#afaire[@]} )); do
        courant="${afaire[$i]}"; i=$(( i + 1 ))
        while [[ "$courant" =~ $RE_SIMPLE ]]; do
            nom="${BASH_REMATCH[1]}"; unset "_REPONSES[$nom]"; courant="${courant//\[\[$nom\]\]/}"
            # un menu : les valeurs que son générateur demande sont oubliées aussi
            [[ "$vus" == *" $nom "* || -z "${GENERATEUR[$nom]:-}" ]] || { vus+="$nom "; afaire+=("${GENERATEUR[$nom]}"); }
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
        # Figée par --list : ses valeurs sont là, ce dont elle dépendait ne
        # compte plus — sinon elle était rejouée pour chaque valeur du parent.
        [[ -z "${LISTE_FIGEE[$nom]:-}" ]] || break
        gen="$(substituer_liaisons "${GENERATEUR[$nom]:-}")"
        [[ "$gen" =~ $RE_LISTE ]] || break
        nom="$(liste_de "${BASH_REMATCH[1]}")"
    done
    printf '%s' "$nom"
}

# expanser <commande> -> _EXP_CMDS (une par combinaison), _EXP_LABELS.
_EXP_CMDS=(); _EXP_LABELS=(); _EXP_TRONQUE=0
expanser() { _EXP_CMDS=(); _EXP_LABELS=(); _EXP_TRONQUE=0; BINDINGS=(); _expanser "$1" "" 0; }
_expanser() {
    local cmd label="$2" prof="$3" cible i val lib rc
    local -a v=() l=()
    (( prof > 6 )) && { erreur "plus de 6 listes emboîtées"; return 1; }
    (( INTERROMPU )) && return 130
    (( _EXP_TRONQUE )) && return 0

    cmd="$(substituer_liaisons "$1")"
    if [[ ! "$cmd" =~ $RE_LISTE ]]; then
        (( ${#_EXP_CMDS[@]} >= TK_MAX_ITERATIONS )) && { _EXP_TRONQUE=1; return 0; }
        _EXP_CMDS+=("$cmd"); _EXP_LABELS+=("$label"); return 0
    fi
    cible="$(liste_a_parcourir "${BASH_REMATCH[1]}")" || return 1
    [[ -n "${GENERATEUR[$cible]:-}${LISTE_FIGEE[$cible]:-}" ]] || {
        erreur "aucune liste « $cible » en section 4 (voir --vars)"; return 1; }
    generer_liste "$cible"; rc=$?
    if (( rc == 2 )); then
        # Branche sans valeur : zéro itération ici, et c'est tout. Au
        # premier niveau on le dit, sinon l'étape entière paraîtrait muette.
        (( prof == 0 )) && attention "la liste « $cible » n'a renvoyé aucune valeur$( (( CODE_LISTE_VIDE )) && printf ' (code %d)' "$CODE_LISTE_VIDE")"
        return 0
    fi
    (( rc != 0 )) && return 1
    v=("${VALEURS[@]}"); l=("${LIBELLES[@]}")

    for i in "${!v[@]}"; do
        (( INTERROMPU )) && return 130
        (( _EXP_TRONQUE )) && return 0
        val="${v[$i]}"; lib="${l[$i]:-$val}"
        BINDINGS["$cible"]="$(echapper_apostrophes "$val")"
        BINDINGS["${cible}_libelle"]="$(echapper_apostrophes "$lib")"
        _expanser "$cmd" "${label:+$label · }$cible=$lib" $(( prof + 1 )); rc=$?
        unset "BINDINGS[$cible]" "BINDINGS[${cible}_libelle]"
        (( rc != 0 )) && return "$rc"
    done
    return 0
}

connu_dans() { local x n="$1"; shift; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }

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
    for e in "${TK_COMMANDES[@]}"; do
        i=$(( i + 1 )); cmd="${e#*|}"; cmd="${cmd#*|}"
        while [[ "$cmd" =~ $RE_SIMPLE ]]; do nom="${BASH_REMATCH[1]}"; _noter PH_SIMPLES USAGE_SIMPLES "$nom" "$i"; cmd="${cmd//\[\[$nom\]\]/}"; done
        while [[ "$cmd" =~ $RE_LISTE ]];  do nom="${BASH_REMATCH[1]}"; cmd="${cmd//\{\{$nom\}\}/}"; _noter PH_LISTES USAGE_LISTES "$(liste_de "$nom")" "$i"; done
    done
    # Une question [[nom]] qui a une liste du même nom est un menu : son
    # générateur peut demander d'autres valeurs, il faut le lire aussi.
    local -a listes_vues=()
    while (( k < ${#PH_LISTES[@]} + ${#PH_SIMPLES[@]} )); do
        if (( k < ${#PH_LISTES[@]} )); then nom="${PH_LISTES[$k]}"; else nom="${PH_SIMPLES[$(( k - ${#PH_LISTES[@]} ))]}"; fi
        k=$(( k + 1 )); gen="${GENERATEUR[$nom]:-}"
        [[ -n "$gen" ]] || continue
        connu_dans "$nom" ${listes_vues[@]+"${listes_vues[@]}"} && continue; listes_vues+=("$nom")
        while [[ "$gen" =~ $RE_SIMPLE ]]; do e="${BASH_REMATCH[1]}"; gen="${gen//\[\[$e\]\]/}"; _noter PH_SIMPLES USAGE_SIMPLES "$e" "et par la liste $nom"; done
        while [[ "$gen" =~ $RE_LISTE ]];  do e="${BASH_REMATCH[1]}"; gen="${gen//\{\{$e\}\}/}"; _noter PH_LISTES USAGE_LISTES "$(liste_de "$e")" "et par la liste $nom"; done
    done
    unset -f _noter
}


# --- 8.6 Exécution ---------------------------------------------------
analyser_validation() {   # "true,log" -> _F_VALIDER _F_LOG _F_STOP _F_CONTINU ; 1 si invalide
    local o; _F_VALIDER=""; _F_LOG=0; _F_STOP=0; _F_CONTINU=0; _MSG_VALIDATION=""
    local -a mots
    IFS=, read -r -a mots <<< "${1,,}"
    for o in ${mots[@]+"${mots[@]}"}; do
        o="${o//[[:space:]]/}"
        case "$o" in
            true|vrai|oui|1) _F_VALIDER="true" ;;  false|faux|non|0) _F_VALIDER="false" ;;
            log) _F_LOG=1 ;;  stop) _F_STOP=1 ;;  continu|continue) _F_CONTINU=1 ;;  "") ;;
            *) _MSG_VALIDATION="option inconnue « $o »"; return 1 ;;
        esac
    done
    [[ -n "$_F_VALIDER" ]] || { _MSG_VALIDATION="il manque true ou false"; return 1; }
    (( _F_STOP && _F_CONTINU )) && { _MSG_VALIDATION="stop et continu s'excluent"; return 1; }
    return 0
}

# executer_une <commande> <log 0/1> : code de la commande ; _DUREE_S posé.
_DUREE_S=0
executer_une() {
    local _debut=$SECONDS _rc
    INTERROMPU=0; journal "$1"
    [[ "$_SIMULATION" == "true" ]] && { _DUREE_S=0; return 0; }
    printf '%s' "$SORTIE_GRISE"
    if (( $2 )); then
        # Un tube et non une substitution de processus : le shell attend tee,
        # et PIPESTATUS donne le vrai code. La commande perd son terminal :
        # d'où l'option explicite. L'estompage est écrit avant le tube : il
        # va au terminal, pas dans le journal.
        eval "$1" 2>&1 | tee -a "$_LOG"; _rc=${PIPESTATUS[0]}
    else
        eval "$1"; _rc=$?
    fi
    printf '%s' "$C0"
    # Une sortie sans retour à la ligne final laissait le curseur au milieu
    # de la ligne, et le verdict venait s'y coller. On remplit la ligne
    # d'espaces : si le curseur était en cours de route, on passe à la
    # suivante ; s'il était au début, l'affichage d'après les recouvre.
    [[ -t 1 ]] && printf '%*s\r' $(( _LARGEUR_TTY - 1 )) ''
    retablir_shell
    _DUREE_S=$(( SECONDS - _debut )); duree "$_DUREE_S"; journal "code $_rc en $DUREE_TXT"
    return "$_rc"
}

# executer_groupe <une par une 0/1> <répétée 0/1> : joue _EXP_CMDS.
# Résultat dans _G_OK _G_KO _G_SKIP _G_INT _G_ARRET(1 boucle, 2 script) _G_RC _G_DUREE, _ITERS.
_G_OK=0; _G_KO=0; _G_SKIP=0; _G_INT=0; _G_ARRET=0; _G_DUREE=0; _G_RC=0; _ITERS=()
executer_groupe() {
    local _upu="$1" _rep="$2" _n=${#_EXP_CMDS[@]} _i _rc _choix _ign=0 _debut=$SECONDS _rang
    _G_OK=0; _G_KO=0; _G_SKIP=0; _G_INT=0; _G_ARRET=0; _G_RC=0; _ITERS=()

    for _i in "${!_EXP_CMDS[@]}"; do
        if (( _rep )); then
            printf -v _rang '%d/%d' $(( _i + 1 )) "$_n"
            couper "${_EXP_LABELS[$_i]}" $(( _LARGEUR - 9 - ${#_rang} ))
            printf '\n  %s──%s %s%s%s %s──%s %s%s%s\n' "$ESTOMPE" "$C0" "$GRAS" "$_rang" "$C0" \
                   "$ESTOMPE" "$C0" "$C_BOUCLE" "$COUPE" "$C0"
            afficher_commande "${_EXP_CMDS[$_i]}" "     "
        fi
        if (( _upu )); then
            menu "Entrée=exécuter" "p=passer" "t=tout enchaîner" "q=arrêter la boucle"
            _choix=""; lire "$(invite)" _choix
            case "${_choix,,}" in
                p) printf '     %s⊘  passée%s\n' "$ESTOMPE" "$C0"; _G_SKIP=$(( _G_SKIP + 1 )); _ITERS+=("skip|passee|${_EXP_LABELS[$_i]}"); continue ;;
                q) printf '     %sboucle arrêtée%s\n' "$C_WARN" "$C0"; _G_ARRET=1; break ;;
                t) _upu=0 ;;
            esac
        fi

        executer_une "${_EXP_CMDS[$_i]}" "$_F_LOG"; _rc=$?

        if (( INTERROMPU )); then
            INTERROMPU=0
            duree "$_DUREE_S"
            printf '  %s⊗  interrompu%s %sau bout de %s%s\n' "$C_WARN" "$C0" "$ESTOMPE" "$DUREE_TXT" "$C0"
            _G_INT=$(( _G_INT + 1 )); _ITERS+=("int|$DUREE_TXT|${_EXP_LABELS[$_i]}")
            (( _rep )) || break
            demander_oui_non "  Continuer la boucle ? ${ESTOMPE}[O/n]${C0} " && continue
            _G_ARRET=1; break
        fi
        if (( _rc == 0 )); then
            if [[ "$_SIMULATION" == "true" ]]; then
                printf '  %s◌  simulée%s\n' "$C_SIM" "$C0"; _ITERS+=("sim|simulee|${_EXP_LABELS[$_i]}")
            else
                duree "$_DUREE_S"
                printf '  %s●  terminée%s %sen %s%s\n' "$C_OK" "$C0" "$ESTOMPE" "$DUREE_TXT" "$C0"; _ITERS+=("ok|$DUREE_TXT|${_EXP_LABELS[$_i]}")
            fi
            _G_OK=$(( _G_OK + 1 )); continue
        fi

        duree "$_DUREE_S"
        printf '  %s✗  échec%s %s— code %d, %s%s\n' "$C_KO" "$C0" "$ESTOMPE" "$_rc" "$DUREE_TXT" "$C0"
        _G_KO=$(( _G_KO + 1 )); _G_RC=$_rc; _ITERS+=("ko|code $_rc|${_EXP_LABELS[$_i]}")
        (( _F_CONTINU )) && { info "(étape marquée « continu » : on poursuit)"; continue; }
        (( _F_STOP ))    && { erreur "étape marquée « stop » : arrêt du script."; _G_ARRET=2; break; }
        (( _ign ))   && continue
        if (( _rep )); then
            menu "Entrée=continuer" "t=continuer sans redemander" "n=arrêter la boucle" "q=quitter"
            _choix=""; lire "$(invite)" _choix
            case "${_choix,,}" in t) _ign=1 ;; n) _G_ARRET=1; break ;; q) _G_ARRET=2; break ;; esac
        else
            demander_oui_non "  Continuer quand même ? ${ESTOMPE}[O/n]${C0} " || _G_ARRET=2
        fi
    done
    _G_DUREE=$(( SECONDS - _debut ))
    return 0
}

resume_iterations() {
    local n=${#_EXP_CMDS[@]} i max=6
    printf '  %s↻  étape répétée%s — %s%d itération%s%s\n' "$C_BOUCLE" "$C0" "$GRAS" "$n" "$(pluriel "$n")" "$C0"
    for (( i = 0; i < n && i < max; i++ )); do
        couper "${_EXP_LABELS[$i]}" $(( _LARGEUR - 9 ))
        printf '     %s%2d%s  %s%s%s\n' "$ESTOMPE" $(( i + 1 )) "$C0" "$C_BOUCLE" "$COUPE" "$C0"
    done
    (( n > max )) && printf '     %s..  et %d autre%s — « l » pour tout voir%s\n' "$ESTOMPE" $(( n - max )) "$(pluriel "$(( n - max ))")" "$C0"
    (( _EXP_TRONQUE )) && attention "limite de $TK_MAX_ITERATIONS itération$(pluriel "$TK_MAX_ITERATIONS") atteinte, liste tronquée (TK_MAX_ITERATIONS, section 2)"
    return 0
}
lister_iterations() {
    local i; printf '\n'
    for i in "${!_EXP_CMDS[@]}"; do
        couper "${_EXP_LABELS[$i]}" $(( _LARGEUR - 10 ))
        printf '     %s%3d%s  %s%s%s\n' "$GRAS" $(( i + 1 )) "$C0" "$C_BOUCLE" "$COUPE" "$C0"
        afficher_commande "${_EXP_CMDS[$i]}" "          "
    done
    printf '\n'
}


# --- 8.7 Plan, récapitulatif, rapport --------------------------------
_RECAP=()                # "num|état|détail|titre"
declare -A _ENFANTS=()   # num -> itérations "état|détail|étiquette", séparées par \x01
_NB_OK=0; _NB_KO=0; _NB_PASSEES=0
DEBUT_HORODATE="$(date '+%F %T %z')"

plan_initial() {   # [oui] = avec les commandes
    local i=0 e reste m
    local -a etats=() marques=()
    for e in "${TK_COMMANDES[@]}"; do
        i=$(( i + 1 )); reste="${e#*|}"; analyser_validation "${reste%%|*}"
        m=""   # seul l'inhabituel est signalé : « auto » plutôt que « confirmation »
        [[ "${reste#*|}" == *"{{"* ]] && m+="${m:+ · }↻ répétée"
        [[ "$_F_VALIDER" == "false" && "$TK_TOUT_VALIDER" != "true" ]] && m+="${m:+ · }auto"
        (( _F_LOG ))     && m+="${m:+ · }log"
        (( _F_STOP ))    && m+="${m:+ · }stop"
        (( _F_CONTINU )) && m+="${m:+ · }continu"
        if etape_retenue "$i"; then etats+=(todo); marques+=("$m")
        else etats+=(skip); marques+=("hors filtre"); fi
    done
    poser_colonne ${marques[@]+"${marques[@]}"}
    printf '\n'; regle "$GRAS"
    printf ' %sPlan%s   %s%d étape%s%s\n' "$C_TITRE" "$C0" "$ESTOMPE" "$_TOTAL" "$(pluriel "$_TOTAL")" "$C0"
    regle "$GRAS"
    for i in "${!TK_COMMANDES[@]}"; do
        e="${TK_COMMANDES[$i]}"
        ligne_tache "${etats[$i]}" $(( i + 1 )) "${e%%|*}" "${marques[$i]}"
        [[ "${1:-}" == "oui" ]] && { reste="${e#*|}"; afficher_commande "${reste#*|}" "        "; }
    done
    [[ "${1:-}" == "oui" ]] && regle
    return 0
}

# _DEMARRE passe à 1 juste avant la première étape : avant ça — -l, --vars,
# une erreur de configuration — il n'y a rien à récapituler. Après, même
# sans une seule étape terminée (un kill pendant la première), l'en-tête,
# la durée et le rapport valent mieux que rien.
_DEMARRE=0

# recap_ajouter <état> <détail> — une ligne du récapitulatif et le compteur
# qui va avec, au lieu de les tenir à la main aux quinze endroits qui en
# ajoutent une. Le titre est figé ici, avec les valeurs connues à l'instant.
recap_ajouter() {
    _RECAP+=("$_NUM|$1|$2|$(titre_lisible "$_TITRE")")
    case "$1" in
        ok)       _NB_OK=$(( _NB_OK + 1 )); marquer_faite "$_CLE" ;;
        ko)       _NB_KO=$(( _NB_KO + 1 )) ;;
        skip|int) _NB_PASSEES=$(( _NB_PASSEES + 1 )) ;;
    esac
    return 0
}
# recap_retirer — défait la dernière ligne : l'étape va être rejouée.
recap_retirer() {
    local e="${_RECAP[-1]#*|}"; e="${e%%|*}"
    case "$e" in
        ok)       _NB_OK=$(( _NB_OK - 1 )) ;;
        ko)       _NB_KO=$(( _NB_KO - 1 )) ;;
        skip|int) _NB_PASSEES=$(( _NB_PASSEES - 1 )) ;;
    esac
    unset '_RECAP[-1]'
    return 0
}

recap() {
    (( ${#_RECAP[@]} == 0 && _DEMARRE == 0 )) && return
    suivre_fenetre
    local l num e d t
    local TOTAL_TXT
    duree "$SECONDS"; TOTAL_TXT="$DUREE_TXT"
    local -a details=()
    for l in ${_RECAP[@]+"${_RECAP[@]}"}; do d="${l#*|}"; d="${d#*|}"; details+=("${d%%|*}"); done
    poser_colonne ${details[@]+"${details[@]}"}
    printf '\n'; regle "$GRAS"
    printf ' %sRécapitulatif%s   %s%s%s\n' "$C_TITRE" "$C0" "$ESTOMPE" "$TK_SUJET" "$C0"
    regle "$GRAS"
    for l in ${_RECAP[@]+"${_RECAP[@]}"}; do
        num="${l%%|*}"; l="${l#*|}"; e="${l%%|*}"; l="${l#*|}"; d="${l%%|*}"; t="${l#*|}"
        ligne_tache "$e" "$num" "$t" "$d"
        recap_enfants "$num"
    done
    regle
    printf '  %s%d réussie%s%s · %s%d en échec%s · %s%d passée%s%s · total %s\n' \
           "$C_OK" "$_NB_OK" "$(pluriel "$_NB_OK")" "$C0" "$( (( _NB_KO )) && printf '%s' "$C_KO" )" "$_NB_KO" "$C0" \
           "$ESTOMPE" "$_NB_PASSEES" "$(pluriel "$_NB_PASSEES")" "$C0" "$TOTAL_TXT"
    printf '  %sjournal  %s%s\n' "$ESTOMPE" "$_LOG" "$C0"
    ecrire_rapport
}
au_revoir() { restaurer_terminal; recap; }
trap au_revoir EXIT

# Au-delà de dix itérations, seules celles qui ont mal tourné sont montrées.
recap_enfants() {
    local brut="${_ENFANTS[$1]:-}" i n e d t caches=0 tout=0 marge
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
        repeter ' ' $(( _LARG_NUM + 4 )); marge="$REPET"
        pad_droite "$t" $(( _COL_BLOC - 3 ))
        printf '%s%s%s%s %s %s  %s%s%s\n' "$marge" "$ESTOMPE" "$( (( i == n - 1 && caches == 0 )) && printf '└─' || printf '├─')" "$C0" \
               "${GLYPHE[$e]:- }" "$PAD" "$ESTOMPE" "$d" "$C0"
    done
    (( caches > 0 )) && { repeter ' ' $(( _LARG_NUM + 4 ))
        printf '%s%s└─ … et %d itération%s réussie%s%s\n' "$REPET" "$ESTOMPE" "$caches" "$(pluriel "$caches")" "$(pluriel "$caches")" "$C0"; }
    return 0
}

ecrire_rapport() {
    [[ -d "${TK_DIR_LOGS:-}" ]] || return 0
    local f="$TK_DIR_LOGS/${TK_PREFIX}_rapport.txt" l num e d t ligne enfants
    {
        printf 'Rapport %s\n  sujet      %s\n' "$NOM_SCRIPT" "$TK_SUJET"
        for l in ${TK_DETAILS[@]+"${TK_DETAILS[@]}"}; do
            if [[ "$l" == *=* ]]; then printf '  %-10s %s\n' "${l%%=*}" "${l#*=}"; else printf '  %s\n' "$l"; fi
        done
        printf '  par        %s%s sur %s\n' "$TK_OPERATEUR" "$( (( EUID == 0 )) && printf ' (root)')" "$(hostname 2>/dev/null || printf '?')"
        duree "$SECONDS"
        printf '  debut      %s\n  fin        %s\n  duree      %s\n\n' "$DEBUT_HORODATE" "$(date '+%F %T %z')" "$DUREE_TXT"
        for l in ${_RECAP[@]+"${_RECAP[@]}"}; do
            num="${l%%|*}"; l="${l#*|}"; e="${l%%|*}"; l="${l#*|}"; d="${l%%|*}"; t="${l#*|}"
            printf '  %2s  %-12s %-10s %s\n' "$num" "${GLYPHE_TXT[$e]:-?}" "$d" "$(titre_lisible "$t")"
            # Les itérations sont jointes par \x01 : il faut les redécouper,
            # sinon tout le groupe tient sur une ligne illisible.
            enfants="${_ENFANTS[$num]:-}"
            while IFS= read -r ligne; do
                [[ -n "$ligne" ]] || continue
                e="${ligne%%|*}"; d="${ligne#*|}"; t="${d#*|}"; d="${d%%|*}"
                printf '        %-12s %-10s %s\n' "${GLYPHE_TXT[$e]:-?}" "$d" "$t"
            done <<< "${enfants//$'\x01'/$'\n'}"
        done
        printf '\n  %d reussies, %d en echec, %d passees\n' "$_NB_OK" "$_NB_KO" "$_NB_PASSEES"
    } 2>/dev/null > "$f" && printf '  %srapport  %s%s\n' "$ESTOMPE" "$f" "$C0" \
        || attention "rapport non écrit : $f"
}


# --- 8.8 Contrôles de départ -----------------------------------------
(( _TOTAL > 0 )) || { erreur "le tableau TK_COMMANDES est vide (section 3, ou votre fichier -c)."; exit 1; }
for e in "${TK_COMMANDES[@]}"; do
    reste="${e#*|}"
    [[ "$e" == *"|"* && "$reste" == *"|"* ]] || { erreur "format attendu Titre|validation|commande :"; printf '  %s\n' "$e" >&2; exit 1; }
    # Une commande réduite à des espaces passerait eval sans rien faire et
    # serait comptée réussie : c'est le pire des cas, on l'attrape ici.
    cmd_nue="${reste#*|}"; cmd_nue="${cmd_nue//[[:space:]]/}"
    [[ -n "$cmd_nue" ]] || { erreur "commande vide :"; printf '  %s\n' "$e" >&2; exit 1; }
    titre_nu="${e%%|*}"; titre_nu="${titre_nu//[[:space:]]/}"
    [[ -n "$titre_nu" ]] || { erreur "titre vide :"; printf '  %s\n' "$e" >&2; exit 1; }
    analyser_validation "${reste%%|*}" || { erreur "validation « ${reste%%|*} » : $_MSG_VALIDATION"; printf '  %s\n' "$e" >&2; exit 1; }
done
charger_listes
scanner_placeholders

etape_retenue() {   # <n> : passe --only et --from ?
    local m
    (( _DEPUIS > 0 && $1 < _DEPUIS )) && return 1
    [[ -n "$_FILTRE_ETAPES" ]] || return 0
    for m in "${_morceaux[@]}"; do
        if [[ "$m" == *-* ]]; then (( $1 >= 10#${m%-*} && $1 <= 10#${m#*-} )) && return 0
        else (( $1 == 10#$m )) && return 0; fi
    done
    return 1
}

if [[ "$_LISTER_VARS" == "true" ]]; then
    printf '\n'
    (( ${#PH_SIMPLES[@]} + ${#PH_LISTES[@]} > 0 )) || info "aucune valeur à fournir."
    for i in ${PH_SIMPLES[@]+"${!PH_SIMPLES[@]}"}; do
        printf '  %s[[%s]]%s  %s%s · %s %s%s\n' "$C_PROG" "${PH_SIMPLES[$i]}" "$C0" "$ESTOMPE" \
               "$( [[ -n "${GENERATEUR[${PH_SIMPLES[$i]}]:-}" ]] && printf menu || printf saisie)" "$(etapes_mot "${USAGE_SIMPLES[$i]}")" "$(sans_et "${USAGE_SIMPLES[$i]}")" "$C0"
    done
    for i in ${PH_LISTES[@]+"${!PH_LISTES[@]}"}; do
        printf '  %s{{%s}}%s  %s%s %s%s\n         %s\n' "$C_BOUCLE" "${PH_LISTES[$i]}" "$C0" "$ESTOMPE" "$(etapes_mot "${USAGE_LISTES[$i]}")" "$(sans_et "${USAGE_LISTES[$i]}")" "$C0" "${GENERATEUR[${PH_LISTES[$i]}]:-(figée)}"
    done
    printf '\n  %s--var nom=valeur répond à une [[question]], --list nom=a,b fige une {{liste}}%s\n\n' "$ESTOMPE" "$C0"
    exit 0
fi

for p in ${PRESETS[@]+"${PRESETS[@]}"}; do
    nom="${p%%=*}"; val="${p#*=}"
    [[ "$p" == *=* && "$nom" =~ ^[a-zA-Z0-9_]+$ ]] || { erreur "--var attend nom=valeur : $p"; exit 1; }
    valeur_valide "$val" || exit 1
    connu_dans "$nom" ${PH_SIMPLES[@]+"${PH_SIMPLES[@]}"} || { erreur "aucun [[$nom]] dans les commandes (voir --vars)"; exit 1; }
    _REPONSES["$nom"]="$val"
done
for p in ${PRESETS_LISTE[@]+"${PRESETS_LISTE[@]}"}; do
    nom="${p%%=*}"; val="${p#*=}"
    [[ "$p" == *=* && "$nom" =~ ^[a-zA-Z0-9_]+$ && -n "$val" ]] || { erreur "--list attend nom=v1,v2 : $p"; exit 1; }
    connu_dans "$nom" ${PH_LISTES[@]+"${PH_LISTES[@]}"} || { erreur "aucune liste « $nom » utilisée (voir --vars)"; exit 1; }
    IFS=, read -r -a _vals <<< "$val"
    for v in "${_vals[@]}"; do valeur_valide "$v" || { erreur "--list $nom : valeur refusée « $v »"; exit 1; }; done
    LISTE_FIGEE["$nom"]="${val//,/$'\n'}"
done

if [[ "$_LISTER_ETAPES" == "true" ]]; then plan_initial oui; printf '\n'; exit 0; fi

# En simulation, un contrôle qui échoue n'empêche pas de voir le plan.
if ! verifier; then [[ "$_SIMULATION" == "true" ]] && attention "contrôles en échec — simulation quand même" || exit 1; fi
[[ "$_INTERACTIF" == "non" && "$_SANS_QUESTION" != "true" ]] && attention "aucun terminal : les réponses seront lues sur l'entrée standard (-y pour ne rien demander)"
MANQUANTS=""; for b in ${TK_REQUIS[@]+"${TK_REQUIS[@]}"}; do command -v "$b" >/dev/null 2>&1 || MANQUANTS+=" $b"; done
[[ -n "$MANQUANTS" ]] && attention "binaires absents :$MANQUANTS"

# sudo demande son mot de passe sur le terminal, au moment où la commande
# part — donc au milieu du déroulé. Avec -y, personne n'est là pour
# répondre et le script attendrait indéfiniment.
if (( EUID != 0 )) && printf '%s\n' "${TK_COMMANDES[@]}" ${TK_LISTES[@]+"${TK_LISTES[@]}"} | grep -qw sudo; then
    if [[ "$_SANS_QUESTION" == "true" ]]; then
        attention "des étapes utilisent sudo : lancez « sudo -v » avant, sinon -y restera bloqué sur la demande de mot de passe"
    else
        info "des étapes utilisent sudo : le mot de passe sera demandé au moment voulu"
    fi
fi

CREES=0
for nom in ${!TK_DIR_@}; do
    d="${!nom}"
    [[ -n "$d" ]] || { erreur "$nom est vide."; exit 1; }
    if [[ ! -d "$d" && "$_SIMULATION" != "true" ]]; then
        mkdir -p "$d" || { erreur "création impossible : $d"; exit 1; }; CREES=$(( CREES + 1 ))
    fi
    [[ "$_SIMULATION" == "true" || -w "$d" ]] || attention "dossier non inscriptible : $d"
done
# Le 2>/dev/null vient AVANT la redirection qu'il fait taire : bash les pose
# de gauche à droite, et c'est l'ouverture du fichier qui échoue. Dans l'autre
# sens, l'erreur de bash s'affiche avant la nôtre. Idem pour le rapport.
[[ "$_SIMULATION" == "true" ]] || { _LOG="$TK_DIR_LOGS/${TK_PREFIX}_script.log"; : 2>/dev/null >> "$_LOG" || { erreur "journal non inscriptible : $_LOG"; exit 1; }; }

# Reprise : empreinte du titre ET de la commande, une par étape réussie.
# Sans -r on repart de zéro : l'état est celui de la dernière exécution, pas
# le cumul de toutes — une étape réussie la semaine dernière et ratée hier
# ne doit pas être sautée aujourd'hui.
_ETAT="$TK_DIR_LOGS/${TK_PREFIX}_etat.txt"
[[ "$_REPRENDRE" == "true" || "$_SIMULATION" == "true" ]] || : 2>/dev/null > "$_ETAT"
empreinte() {
    if command -v sha1sum >/dev/null 2>&1; then printf '%s' "$1" | sha1sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum | cut -d' ' -f1
    else printf '%s' "$1" | cksum | tr -d ' '; fi
}
deja_faite()   { [[ "$_REPRENDRE" == "true" && -r "$_ETAT" ]] && grep -qxF "$1" "$_ETAT" 2>/dev/null; }
marquer_faite() { [[ "$_SIMULATION" == "true" ]] || printf '%s\n' "$1" >> "$_ETAT" 2>/dev/null || true; }

printf '\n'; regle "$GRAS"
printf ' %s%s%s  %s%s%s\n' "$GRAS" "$NOM_SCRIPT" "$C0" "$C_ACCENT" "$TK_SUJET" "$C0"
regle "$GRAS"
for l in ${TK_DETAILS[@]+"${TK_DETAILS[@]}"}; do
    if [[ "$l" == *=* ]]; then entete "${l%%=*}" "${l#*=}"; else info "$l"; fi
done
entete "sortie"   "${TK_DIR_LOGS%/*}$( (( CREES > 0 )) && printf '  (%d dossier%s créé%s)' "$CREES" "$(pluriel "$CREES")" "$(pluriel "$CREES")")"
entete "par"      "$TK_OPERATEUR$( (( EUID == 0 )) && printf ' (root)')"
entete "journal"  "$_LOG"
[[ -n "$_CONF" ]]                 && entete "config"     "$_CONF"
[[ "$_SIMULATION" == "true" ]]    && entete "dry-run"    "rien ne sera exécuté"
[[ "$_SANS_QUESTION" == "true" ]] && entete "-y"         "aucune question ne sera posée"
[[ "$TK_TOUT_VALIDER" == "true" ]]  && entete "-a"         "chaque étape sera confirmée"
[[ "$_REPRENDRE" == "true" ]]     && entete "resume"     "les étapes déjà réussies seront sautées"
[[ -n "$_FILTRE_ETAPES" ]]        && entete "only"       "étapes $_FILTRE_ETAPES"
(( _DEPUIS > 0 ))                 && entete "from"       "étape $_DEPUIS"
[[ -n "$TK_INTRO" ]] && printf '\n%s\n' "$TK_INTRO"
journal "=== démarrage — $TK_SUJET — par $TK_OPERATEUR"
plan_initial


# --- 8.9 Une étape ---------------------------------------------------
# Tout ce qui arrive à une étape, du titre au récapitulatif : la reprise,
# la résolution des valeurs, l'expansion des listes, le dialogue, et le
# verdict. Rend 1 si --only ou --from l'écartent, 0 sinon.
jouer_etape() {
    local entree="$1" e
    suivre_fenetre          # la fenêtre a pu changer depuis l'étape d'avant
    local _TITRE _RESTE _BRUTE _OCC _CLE _CMDBASE _NOUVELLE _BILAN _CHOIX
    local _BESOIN_EXP _RCEXP _NB_ITER _REPETEE _UNE_PAR_UNE
    # Le titre garde ses [[nom]] : c'est la clé de --resume et ce qu'affiche
    # le plan. Au récapitulatif il est figé avec les valeurs du moment, pour
    # qu'une valeur ressaisie plus tard ne réécrive pas l'étape déjà jouée.
    _TITRE="${entree%%|*}"; _RESTE="${entree#*|}"; _BRUTE="${_RESTE#*|}"
    analyser_validation "${_RESTE%%|*}"
    etape_retenue "$_NUM" || return 1

    # Deux étapes identiques ont deux clés : sinon l'échec de la seconde
    # serait masqué par la réussite de la première au prochain --resume.
    _OCC=0; for e in "${TK_COMMANDES[@]:0:_NUM-1}"; do [[ "$e" == "$entree" ]] && _OCC=$(( _OCC + 1 )); done
    _CLE="$(empreinte "$_TITRE|$_BRUTE|$_OCC")"
    if deja_faite "$_CLE"; then
        titre_etape "$_NUM" "$_TOTAL" "$_TITRE"; info "déjà réussie précédemment — sautée (--resume)"
        recap_ajouter skip reprise; return 0
    fi

    titre_etape "$_NUM" "$_TOTAL" "$_TITRE"
    INTERROMPU=0; _ETAPE_PASSEE=0
    if ! resoudre_simples "$_BRUTE"; then
        recap_ajouter skip passee; journal "PASSÉE : $_TITRE"; return 0
    fi
    _CMDBASE="$_CMD"; _BESOIN_EXP=1

    while true; do
        if (( _BESOIN_EXP )); then
            _ETAPE_PASSEE=0          # un « p » donné pendant une édition annulée ne compte plus
            expanser "$_CMDBASE"; _RCEXP=$?; _BESOIN_EXP=0
            if (( _ETAPE_PASSEE )); then
                recap_ajouter skip passee; journal "PASSÉE : $_TITRE"; break
            fi
            if (( INTERROMPU )); then
                INTERROMPU=0; attention "lecture des listes interrompue — étape abandonnée"
                recap_ajouter int listes; break
            fi
            if (( _RCEXP != 0 || ${#_EXP_CMDS[@]} == 0 )); then
                erreur "les listes de cette étape n'ont rien donné : rien à exécuter."
                info "vérifiez la commande de liste (--vars), ou figez-la avec --list"
                recap_ajouter ko "liste vide"
                if [[ "$_SANS_QUESTION" != "true" ]]; then
                    menu "Entrée=passer à la suite" "r=ressaisir les valeurs" "q=quitter"
                    _CHOIX=""; lire "$(invite)" _CHOIX
                    case "${_CHOIX,,}" in
                        r) oublier_valeurs "$_BRUTE"
                           if resoudre_simples "$_BRUTE"; then
                               _CMDBASE="$_CMD"; _BESOIN_EXP=1; recap_retirer; continue
                           fi ;;
                        q) quitter 1 ;;
                    esac
                fi
                break
            fi
        fi

        _NB_ITER=${#_EXP_CMDS[@]}; _REPETEE=0
        [[ $_NB_ITER -gt 1 || -n "${_EXP_LABELS[0]}" ]] && _REPETEE=1
        if (( _REPETEE )); then resume_iterations; else afficher_commande "${_EXP_CMDS[0]}"; fi
        (( _F_LOG ))     && info "la sortie est recopiée dans le journal"
        (( _F_STOP ))    && info "un échec ici arrête le script"
        (( _F_CONTINU )) && info "un échec ici est ignoré, sans question"

        _CHOIX=""   # vide = exécuter : les étapes « false » partent seules
        if [[ "$_F_VALIDER" == "true" || "$TK_TOUT_VALIDER" == "true" ]]; then
            if (( _REPETEE )); then menu "Entrée=tout exécuter" "u=une par une" "l=lister" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"
            else menu "Entrée=exécuter" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"; fi
            lire "$(invite)" _CHOIX
        fi

        case "${_CHOIX,,}" in
            ""|o|oui|y|yes|u|t)
                _UNE_PAR_UNE=0; [[ "${_CHOIX,,}" == "u" ]] && _UNE_PAR_UNE=1
                executer_groupe "$_UNE_PAR_UNE" "$_REPETEE"
                (( _REPETEE && ${#_ITERS[@]} > 0 )) && _ENFANTS["$_NUM"]="$(printf '%s\x01' "${_ITERS[@]}")"

                if (( _REPETEE )); then
                    duree "$_G_DUREE"
                    if [[ "$_SIMULATION" == "true" ]]; then recap_ajouter sim "$_NB_ITER iter"
                    elif (( _G_KO == 0 && _G_INT == 0 && _G_SKIP == 0 && _G_ARRET == 0 )); then
                        recap_ajouter ok "$_G_OK/$_NB_ITER$( (( _EXP_TRONQUE )) && printf ' tronq') $DUREE_TXT"
                    elif (( _G_KO > 0 )); then recap_ajouter ko "$_G_KO KO /$_NB_ITER"
                    else recap_ajouter int "$_G_OK/$_NB_ITER ok"; fi
                    _BILAN="$C_OK$_G_OK réussie$(pluriel "$_G_OK")$C0"
                    (( _G_KO ))   && _BILAN+=" · $C_KO$_G_KO échec$(pluriel "$_G_KO")$C0"
                    (( _G_INT ))  && _BILAN+=" · $C_WARN$_G_INT interrompue$(pluriel "$_G_INT")$C0"
                    (( _G_SKIP )) && _BILAN+=" · $ESTOMPE$_G_SKIP passée$(pluriel "$_G_SKIP")$C0"
                    printf '\n  %s└─%s  %s · %s%s%s\n' "$ESTOMPE" "$C0" "$_BILAN" "$ESTOMPE" "$DUREE_TXT" "$C0"
                elif (( _G_INT )); then
                    duree "$_G_DUREE"; recap_ajouter int "$DUREE_TXT"
                    (( _G_ARRET )) || demander_oui_non "  Passer à l'étape suivante ? ${ESTOMPE}[O/n]${C0} " || quitter 130
                elif (( _G_KO )); then recap_ajouter ko "code $_G_RC"
                elif [[ "$_SIMULATION" == "true" ]]; then recap_ajouter sim simulee
                else duree "$_G_DUREE"; recap_ajouter ok "$DUREE_TXT"; fi
                (( _G_ARRET == 2 )) && quitter 1
                break ;;
            l) lister_iterations ;;
            p) printf '  %s⊘  passée%s\n' "$ESTOMPE" "$C0"; recap_ajouter skip passee; journal "PASSÉE : $_TITRE"; break ;;
            e)  # modification pour cette exécution seulement
                _NOUVELLE=""; lire_edit "$_CMDBASE" _NOUVELLE
                if [[ -z "${_NOUVELLE// /}" ]]; then attention "commande vide : édition annulée"
                elif resoudre_simples "$_NOUVELLE"; then _CMDBASE="$_CMD"; _BESOIN_EXP=1
                else attention "édition annulée"; fi ;;
            r)  # ressaisir les valeurs de CETTE étape seulement
                oublier_valeurs "$_BRUTE"
                if resoudre_simples "$_BRUTE"; then _CMDBASE="$_CMD"; _BESOIN_EXP=1; info "valeurs ressaisies"
                else recap_ajouter skip passee; break; fi ;;
            q) quitter ;;
            *) printf '  %s« %s » n'"'"'est pas une réponse attendue%s\n' "$C_WARN" "$_CHOIX" "$C0" ;;
        esac
    done
    return 0
}


# --- 8.10 Boucle principale ------------------------------------------
_DEMARRE=1
_NUM=0; _NB_FILTREES=0
for entree in "${TK_COMMANDES[@]}"; do
    _NUM=$(( _NUM + 1 ))
    jouer_etape "$entree" || _NB_FILTREES=$(( _NB_FILTREES + 1 ))
done

if (( _NB_FILTREES == _TOTAL )); then
    attention "aucune étape retenue : --only / --from les écartent toutes"
elif (( _NB_FILTREES > 0 )); then
    info "$_NB_FILTREES étape$(pluriel "$_NB_FILTREES") écartée$(pluriel "$_NB_FILTREES") par --only / --from"
fi
(( _NB_KO > 0 )) && exit 1
exit 0
