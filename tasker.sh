#!/usr/bin/env bash
#
# tasker.sh — enchaîne des commandes, validées une à une.
#     ./tasker.sh -h       aide          ./tasker.sh -l       voir le plan
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
DOSSIER="$HOME"                # ce sur quoi on travaille
SORTIE="${TMPDIR:-/tmp}/tasker" # où écrire journal et rapport
OPERATEUR="${SUDO_USER:-${USER:-inconnu}}"   # noté dans le journal et le rapport
TOUT_VALIDER="false"           # true = confirmer chaque étape (ou -a)
MAX_ITERATIONS=500             # au-delà, une étape répétée est tronquée
REQUIS=(du df)                 # binaires attendus ; absents = avertissement


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
#   Le tout est dans une fonction pour que $DOSSIER etc. suivent -c et --set.
#
#   Ce qui suit est un exemple qui tourne partout. Remplacez-le, ou
#   laissez-le et mettez les vôtres dans un fichier -c (voir exemples/).
# =====================================================================
definir_commandes() {

COMMANDES=(
"Espace disponible|false|df -h '$DOSSIER'"
"Contenu du dossier|true|ls -la '$DOSSIER'"
"Taille de chaque sous-dossier|true|du -sh '{{sousdossier}}'"
"Fichiers plus gros que [[taille]]|true,log|find '$DOSSIER' -type f -size +[[taille]] 2>/dev/null | head -n 20"
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
#   UNE LISTE PEUT EN APPELER UNE AUTRE, et c'est tout le mécanisme : une
#   liste qui contient {{sousdossier}} est régénérée pour chaque
#   sous-dossier, et l'écrire seule dans une commande suffit à parcourir
#   les deux niveaux. Une liste vide ne produit aucune itération, ce n'est
#   pas une erreur. Exemple déroulé : TUTORIEL.md.
# =====================================================================
LISTES=(
"sousdossier|lister_dossiers '$DOSSIER'"
"taille|printf '%s\t%s\n' 1M 'un mégaoctet' 10M 'dix mégaoctets' 100M 'cent mégaoctets'"
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
    SUJET="${DOSSIER##*/}"
    DETAILS=("dossier=$DOSSIER")
    PREFIX="$(printf '%s' "${DOSSIER##*/}" | tr -c 'A-Za-z0-9._-' '_')"
    DIR_LOGS="$SORTIE/logs"
}

# Contrôles avant de commencer : renvoyez 1 pour arrêter. Les dossiers et
# les binaires de REQUIS sont déjà vérifiés par ailleurs.
verifier() {
    [[ -d "$DOSSIER" ]] || { erreur "dossier absent : $DOSSIER"
        info "réglez DOSSIER en section 1, ou : --set DOSSIER=/chemin · -c fichier.conf"
        return 1; }
    return 0
}


# =====================================================================
# 5. FONCTIONS
#    Une fonction d'étape termine par return (son code fait ● ou ✗).
#    Une fonction de liste écrit une valeur par ligne, ses erreurs sur >&2.
#    Dans une boucle longue :  (( INTERROMPU )) && return 130
# =====================================================================

# lister_dossiers <racine>
# La fonction de liste la plus simple qui soit : une boucle for sur les
# sous-dossiers d'un répertoire, une ligne « chemin<TAB>nom » par dossier.
# {{sousdossier}} vaut alors le chemin et {{sousdossier_libelle}} le nom.
lister_dossiers() {
    local d
    for d in "$1"/*/; do                  # le / final ne garde que les dossiers
        (( INTERROMPU )) && return 130    # Ctrl-C doit pouvoir sortir de la boucle
        [[ -d "$d" ]] || continue         # aucun dossier : le motif reste tel quel
        d="${d%/}"                        # retire le / final
        printf '%s\t%s\n' "$d" "${d##*/}"  # chemin, tabulation, nom seul
    done
    return 0
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

# Sous une locale POSIX, ${#x} compte les octets : « é » en vaut deux, les
# colonnes se décalent et un repli peut couper un caractère en deux. On
# essaie d'abord de passer bash lui-même en UTF-8 — LC_ALL n'est pas
# exporté, vos commandes gardent leur locale — et sinon on mesure à la main.
_SONDE="é"; UTF8_OK=0
for _loc in "" C.UTF-8 C.utf8 en_US.UTF-8 fr_FR.UTF-8; do
    [[ -n "$_loc" ]] && LC_ALL="$_loc"
    (( ${#_SONDE} == 1 )) && { UTF8_OK=1; break; }
done
(( UTF8_OK )) || unset LC_ALL
LC_ALL_TK="${LC_ALL-__absent__}"   # pour la remettre si une commande la change
unset _SONDE _loc
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

LARG_NUM=2   # largeur des numéros d'étape, recalculée d'après TOTAL
ligne_tache() {   # <état> <numéro> <titre> <détail>
    local ct=""
    case "$1" in ko) ct="$C_KO" ;; int) ct="$C_WARN" ;; skip) ct="$ESTOMPE" ;; sim) ct="$C_SIM" ;; esac
    if [[ -z "$4" ]]; then
        printf '  %s %s%*s%s  %s%s%s\n' "$(glyphe "$1")" "$ESTOMPE" "$LARG_NUM" "$2" "$C0" "$ct" "$3" "$C0"
    else
        printf '  %s %s%*s%s  %s%s%s  %s%s%s\n' "$(glyphe "$1")" "$ESTOMPE" "$LARG_NUM" "$2" "$C0" \
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
# replier <texte> <largeur> -> LIGNES : coupé aux espaces, par caractères.
# fold ferait l'affaire, mais sous une locale POSIX il compte les octets et
# coupe un « é » en deux.
LIGNES=()
replier() {
    local larg="$2" ligne="" mot
    local -a mots=()
    LIGNES=()
    read -r -a mots <<< "$1"
    for mot in ${mots[@]+"${mots[@]}"}; do
        if [[ -z "$ligne" ]]; then ligne="$mot"
        elif (( $(largeur_texte "$ligne $mot") <= larg )); then ligne+=" $mot"
        else LIGNES+=("$ligne"); ligne="$mot"; fi
        # un mot seul plus large que l'écran : coupé net si l'on sait le
        # faire par caractères, sinon laissé déborder plutôt qu'abîmé
        while (( UTF8_OK && ${#ligne} > larg )); do
            LIGNES+=("${ligne:0:larg}"); ligne="${ligne:larg}"
        done
    done
    [[ -n "$ligne" ]] && LIGNES+=("$ligne")
    return 0
}

afficher_commande() {   # <commande> [indentation]
    local ind="${2:-  }" dispo i prog reste
    dispo=$(( LARGEUR - ${#ind} - 2 )); (( dispo < 24 )) && dispo=24
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
    [[ "$SANS_QUESTION" == "true" ]] && return 0
    for e in "$@"; do
        ligne+="${ligne:+$ESTOMPE · $C0}${C_CLE}${e%%=*}${C0} ${ESTOMPE}${e#*=}${C0}"
    done
    printf '  %s\n' "$ligne"
}
invite() { printf '  %s›%s ' "$GRAS" "$C0"; }


# --- 5.2 Aide --------------------------------------------------------
# L'aide : option en cyan, touches en gras, rien d'autre.
h_titre() { printf '\n%s%s%s\n' "$GRAS" "$1" "$C0"; }
h_opt()   { printf '  %s%-26s%s %s\n' "$C_PROG" "$1" "$C0" "$2"; }          # -x, --xx VALEUR   explication
h_cle() {   # <libellé> clé=texte ... — une clé vide n'affiche que le texte
    printf '  %s ' "$(pad_droite "$1" 16)"; shift
    local e k s=""
    for e in "$@"; do k="${e%%=*}"; s+="${s:+ · }${k:+$GRAS$k$C0 }${e#*=}"; done
    printf '%s\n' "$s"
}
aide() {
    printf '%s%s%s — enchaîne des commandes, validées une à une.\n' "$GRAS" "$NOM_SCRIPT" "$C0"
    printf 'Usage : %s./%s%s [options]\n' "$C_PROG" "$NOM_SCRIPT" "$C0"
    h_titre "Configurer"
    h_opt "-c, --config FICHIER" "variables lues dans un fichier"
    h_opt "-t, --template"       "écrire un fichier -c prêt à compléter (sur la sortie standard)"
    h_opt "-s, --set NOM=valeur" "fixer une variable de la section 1"
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
    h_opt "-h, --help"           "cette aide"
    h_titre "Pendant l'exécution"
    h_cle "à une étape"     "Entrée=exécuter" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"
    h_cle "étape répétée"   "u=une par une" "l=lister les itérations"
    h_cle "question posée"  "1 2 3=choisir" "a=autre valeur" "p=passer" "q=quitter"
    h_cle "Ctrl-C"          "=interrompt la commande ; à une question, arrête le script"
    printf '  %-16s %s à faire  %s en cours  %s réussie  %s échec  %s passée  %s interrompue  %s simulée\n' "marques" \
           "$(glyphe todo)" "$(glyphe cours)" "$(glyphe ok)" "$(glyphe ko)" "$(glyphe skip)" "$(glyphe int)" "$(glyphe sim)"
    h_titre "Dans le script   1 variables · 2 commandes · 3 listes · 4 chemins · 5 fonctions"
    printf '  %s"Titre|true|commande"%s   true = demander avant, false = lancer direct\n' "$C_PROG" "$C0"
    printf '  %s[[nom]]%s  une valeur demandée une fois       %s{{nom}}%s  l%sétape rejouée par valeur\n' "$C_PROG" "$C0" "$C_PROG" "$C0" "'"
    printf '  Exemples et détails : TUTORIEL.md            Code de sortie : 1 s%sil reste un échec\n\n' "'"
}

# ---------- --template : un fichier -c déduit de la section 1 du script ----------
# On relit la section 1 de ce fichier même : si vous y ajoutez ou renommez
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
    # qui sont proposées — celles de la section 1 ne le concernent pas.
    if [[ -n "$CONF" ]]; then
        printf 'source "%s"\n\n' "$(readlink -f "$CONF" 2>/dev/null || printf '%s' "$CONF")"
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
    done < <(if [[ -n "$CONF" ]]; then sed '/^[a-zA-Z_][a-zA-Z0-9_]*() *{/,$d' "$CONF" | grep -E '^[A-Za-z_][A-Za-z0-9_]*='
             else sed -n '/^# 1\. VARIABLES/,/^# 2\. COMMANDES/p' "$src"; fi)
    (( ${#deja[@]} > 0 )) || erreur "aucune variable trouvée ${CONF:+dans $CONF}${CONF:-entre « # 1. VARIABLES » et « # 2. COMMANDES » dans $src}"
}


# --- 5.3 Arguments et configuration ----------------------------------
PRESETS=(); PRESETS_LISTE=(); SETS=()
CONF=""; INTRO=""
LISTER_VARS="false"; LISTER_ETAPES="false"; SIMULATION="false"; AIDE="false"; GABARIT="false"
SANS_QUESTION="false"; REPRENDRE="false"; FILTRE_ETAPES=""; DEPUIS=0

exige_valeur() { [[ -n "${2:-}" ]] || { printf '%s attend une valeur.\n' "$1" >&2; exit 1; }; }

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
        -a|--ask)          TOUT_VALIDER="true";  shift ;;
        -y|--yes)          SANS_QUESTION="true"; shift ;;
        -n|--dry-run)      SIMULATION="true";    shift ;;
        -l|--plan)         LISTER_ETAPES="true"; shift ;;
        -r|--resume)       REPRENDRE="true";     shift ;;
        --vars)            LISTER_VARS="true";   shift ;;
        --no-color)        COULEUR="non";        shift ;;
        -D|--var)          exige_valeur "$1" "${2:-}"; PRESETS+=("$2");       shift 2 ;;
        --var=*)           PRESETS+=("${1#*=}");                              shift ;;
        --list)            exige_valeur "$1" "${2:-}"; PRESETS_LISTE+=("$2"); shift 2 ;;
        --list=*)          PRESETS_LISTE+=("${1#*=}");                        shift ;;
        -s|--set)          exige_valeur "$1" "${2:-}"; SETS+=("$2");          shift 2 ;;
        --set=*)           SETS+=("${1#*=}");                                 shift ;;
        -o|--only)         exige_valeur "$1" "${2:-}"; FILTRE_ETAPES="$2";    shift 2 ;;
        --only=*)          FILTRE_ETAPES="${1#*=}";                           shift ;;
        -f|--from)         exige_valeur "$1" "${2:-}"; DEPUIS="$2";           shift 2 ;;
        --from=*)          DEPUIS="${1#*=}";                                  shift ;;
        -c|--config)       exige_valeur "$1" "${2:-}"; CONF="$2";             shift 2 ;;
        --config=*)        CONF="${1#*=}";                                    shift ;;
        --color)           exige_valeur "$1" "${2:-}"; COULEUR="$2";          shift 2 ;;
        --color=*)         COULEUR="${1#*=}";                                 shift ;;
        -t|--template)     GABARIT="true";       shift ;;
        -h|--help)         AIDE="true";          shift ;;
        *) printf 'Option inconnue : %s   (-h pour l'"'"'aide)\n' "$1" >&2; exit 1 ;;
    esac
done
case "$COULEUR" in always|yes|oui) COULEUR="oui" ;; never|no|non) COULEUR="non" ;; auto) ;;
    *) printf -- '--color attend auto, always ou never.\n' >&2; exit 1 ;; esac
init_affichage
[[ "$AIDE" == "true" ]] && { aide; exit 0; }

# Le fichier -c est du shell : il peut fixer les variables, mais aussi
# redéfinir definir_commandes et ajouter des fonctions (voir exemples/).
if [[ -n "$CONF" ]]; then
    [[ -r "$CONF" ]] || { erreur "configuration illisible : $CONF"; exit 1; }
    bash -n "$CONF" 2>/dev/null || { erreur "erreur de syntaxe dans $CONF"; bash -n "$CONF"; exit 1; }
    # Un « exit » dans le fichier tuerait le script sans un mot : on le
    # charge d'abord dans un sous-shell pour le voir venir.
    # shellcheck disable=SC1090
    ( source "$CONF" >/dev/null 2>&1 ) || { erreur "$CONF s'est terminé tout seul (code $?) : un « exit » dedans ? Utilisez return."; exit 1; }
    # shellcheck disable=SC1090
    source "$CONF" || { erreur "échec du chargement de $CONF"; exit 1; }
fi
# --set NOM=valeur : n'importe quelle variable de la section 1. On exige
# qu'elle existe déjà, sinon une faute de frappe passerait inaperçue.
for e in ${SETS[@]+"${SETS[@]}"}; do
    k="${e%%=*}"
    [[ "$e" == *=* && "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { erreur "--set attend NOM=valeur : $e"; exit 1; }
    decl="$(declare -p "$k" 2>/dev/null)" || { erreur "--set : aucune variable « $k » en section 1"; exit 1; }
    [[ "$decl" != "declare -a"* && "$decl" != "declare -A"* ]] || { erreur "--set : « $k » est un tableau, modifiez-le dans le fichier -c"; exit 1; }
    printf -v "$k" '%s' "${e#*=}" 2>/dev/null \
        || { erreur "--set : « $k » ne peut pas être modifiée (lecture seule ?)"; exit 1; }
done
case "${TOUT_VALIDER,,}" in true|oui|1) TOUT_VALIDER="true" ;; *) TOUT_VALIDER="false" ;; esac
[[ "$MAX_ITERATIONS" =~ ^[0-9]+$ ]] && (( MAX_ITERATIONS >= 1 )) \
    || { erreur "MAX_ITERATIONS doit être un entier positif : $MAX_ITERATIONS"; exit 1; }
[[ "$DEPUIS" =~ ^[0-9]+$ ]] || { erreur "--from attend un numéro d'étape"; exit 1; }
DEPUIS=$(( 10#$DEPUIS ))
FILTRE_ETAPES="${FILTRE_ETAPES//[[:space:]]/}"
if [[ -n "$FILTRE_ETAPES" ]]; then
    IFS=, read -r -a _morceaux <<< "$FILTRE_ETAPES"
    for m in "${_morceaux[@]}"; do
        [[ "$m" =~ ^[0-9]+(-[0-9]+)?$ ]] || { erreur "--only : « $m » n'est ni un numéro ni un intervalle"; exit 1; }
        [[ "$m" != *-* ]] || (( 10#${m%-*} <= 10#${m#*-} )) || { erreur "--only : intervalle inversé « $m »"; exit 1; }
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

[[ "$GABARIT" == "true" ]] && { gabarit; exit 0; }

# Un fichier -c peut écrire COMMANDES et LISTES directement, sans passer
# par definir_commandes : on les prend tels quels. Sinon on appelle la
# fonction — d'abord dans un sous-shell, pour transformer un
# « DIR_BODY: unbound variable » en explication.
if declare -p COMMANDES >/dev/null 2>&1; then
    declare -p LISTES >/dev/null 2>&1 || LISTES=()
else
    if ! _err="$( (definir_commandes) 2>&1 )"; then
        erreur "impossible de construire COMMANDES : ${_err##*: }"
        info "une variable utilisée en section 2 ou 3 n'existe pas — votre fichier -c redéfinit calculer_variables sans definir_commandes ?"
        exit 1
    fi
    definir_commandes
fi
TOTAL=${#COMMANDES[@]}
LARG_NUM=${#TOTAL}; (( LARG_NUM < 2 )) && LARG_NUM=2


# --- 5.4 Saisies et signaux ------------------------------------------
# Les questions se lisent sur /dev/tty : l'entrée standard peut être
# prise par une commande.
if (exec 3< /dev/tty) 2>/dev/null; then ENTREE="/dev/tty"; INTERACTIF="oui"
else ENTREE="/dev/stdin"; INTERACTIF="non"; fi

LOG="/dev/null"
journal() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }

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
    local t p
    t="$(ps -o tpgid= -p $$ 2>/dev/null)"; p="$(ps -o pgid= -p $$ 2>/dev/null)"
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
retablir_shell() {
    set +e -u -o pipefail +x +v
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
quitter() {   # [code] — sans argument : 1 s'il y a déjà eu un échec
    printf '\n'; info "arrêt demandé."; journal "ARRÊT demandé"
    exit "${1:-$(( NB_KO > 0 ))}"
}


# --- 5.5 Valeurs, listes, emboîtement --------------------------------
RE_SIMPLE='\[\[([a-zA-Z0-9_]+)\]\]'
RE_LISTE='\{\{([a-zA-Z0-9_]+)\}\}'

# =() est obligatoire : sous set -u, un « declare -A X » nu rend ${#X[@]} illégal.
declare -A REPONSES=()      # [[nom]] -> valeur
declare -A GENERATEUR=()    # liste   -> commande
declare -A CACHE_LISTE=()   # commande résolue -> lignes
declare -A LISTE_FIGEE=()   # --list nom=a,b
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
    [[ "$1" != *$'\n'* ]] || { printf '    %sune valeur tient sur une ligne%s\n' "$JAUNE" "$C0"; return 1; }
    [[ "$1" != *'[['* && "$1" != *'{{'* ]] || { printf '    %s[[ et {{ sont interdits dans une valeur%s\n' "$JAUNE" "$C0"; return 1; }
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
        # </dev/null : une commande de liste qui lit l'entrée standard par
        # accident (cat sans argument) resterait bloquée sans rien dire.
        # sudo, lui, lit /dev/tty et n'est pas gêné.
        sortie="$(eval "$gen" 2>> "$LOG" </dev/null)"; rc=$?
        retablir_shell
        [[ -t 1 ]] && printf '\r%s\r' "$(repeter ' ' $(( ${#nom} + 30 )))"
        # Un code non nul sans aucune sortie n'est pas une erreur : ls, grep
        # ou find rendent justement 1 ou 2 quand ils ne trouvent rien. C'est
        # une liste vide — la branche ne produit rien — et le journal garde
        # le code pour qui veut comprendre.
        if (( rc != 0 && ${#sortie} == 0 )); then journal "LISTE $nom : aucune valeur (code $rc)"; CODE_LISTE_VIDE=$rc; fi
        CACHE_LISTE["$gen"]="${sortie:-$'\001'}"
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
    (( ${#VALEURS[@]} > 0 )) || { journal "LISTE $nom : aucune valeur"; return 2; }
    return 0
}
CODE_LISTE_VIDE=0

# demander_valeur <nom> -> VALEUR ; 1 si l'utilisateur passe l'étape.
VALEUR=""
demander_valeur() {
    local nom="$1" i n choix ou libre=0
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
                q) quitter ;;
            esac
            if [[ "$choix" =~ ^[0-9]+$ ]] && (( 10#$choix >= 1 && 10#$choix <= n )); then
                choix=$(( 10#$choix ))
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
                q) quitter ;;
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
        (( prof == 0 )) && attention "la liste « $cible » n'a renvoyé aucune valeur$( (( CODE_LISTE_VIDE )) && printf ' (code %d)' "$CODE_LISTE_VIDE")"
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
    local _debut=$SECONDS _rc
    INTERROMPU=0; journal "$1"
    [[ "$SIMULATION" == "true" ]] && { DUREE_S=0; return 0; }
    if (( $2 )); then
        # Un tube et non une substitution de processus : le shell attend tee,
        # et PIPESTATUS donne le vrai code. La commande perd son terminal :
        # d'où l'option explicite.
        eval "$1" 2>&1 | tee -a "$LOG"; _rc=${PIPESTATUS[0]}
    else
        eval "$1"; _rc=$?
    fi
    retablir_shell
    DUREE_S=$(( SECONDS - _debut )); journal "code $_rc en $(duree "$DUREE_S")"
    return "$_rc"
}

# executer_groupe <une par une 0/1> <répétée 0/1> : joue EXP_CMDS.
# Résultat dans G_OK G_KO G_SKIP G_INT G_ARRET(1 boucle, 2 script) G_RC G_DUREE, ITERS.
G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_DUREE=0; G_RC=0; ITERS=()
executer_groupe() {
    local _upu="$1" _rep="$2" _n=${#EXP_CMDS[@]} _i _rc _choix _ign=0 _debut=$SECONDS
    G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_RC=0; ITERS=()

    for _i in "${!EXP_CMDS[@]}"; do
        if (( _rep )); then
            printf '\n  %s──%s %s%d/%d%s %s──%s %s%s%s\n' "$ESTOMPE" "$C0" "$GRAS" $(( _i + 1 )) "$_n" "$C0" \
                   "$ESTOMPE" "$C0" "$C_BOUCLE" "${EXP_LABELS[$_i]}" "$C0"
            afficher_commande "${EXP_CMDS[$_i]}" "     "
        fi
        if (( _upu )); then
            menu "Entrée=exécuter" "p=passer" "t=tout enchaîner" "q=arrêter la boucle"
            _choix=""; lire "$(invite)" _choix
            case "${_choix,,}" in
                p) printf '     %s⊘  passée%s\n' "$ESTOMPE" "$C0"; G_SKIP=$(( G_SKIP + 1 )); ITERS+=("skip|passee|${EXP_LABELS[$_i]}"); continue ;;
                q) printf '     %sboucle arrêtée%s\n' "$JAUNE" "$C0"; G_ARRET=1; break ;;
                t) _upu=0 ;;
            esac
        fi

        executer_une "${EXP_CMDS[$_i]}" "$F_LOG"; _rc=$?

        if (( INTERROMPU )); then
            INTERROMPU=0
            printf '  %s⊗  interrompu%s %sau bout de %s%s\n' "$C_WARN" "$C0" "$ESTOMPE" "$(duree "$DUREE_S")" "$C0"
            G_INT=$(( G_INT + 1 )); ITERS+=("int|$(duree "$DUREE_S")|${EXP_LABELS[$_i]}")
            (( _rep )) || break
            demander_oui_non "  Continuer la boucle ? ${ESTOMPE}[O/n]${C0} " && continue
            G_ARRET=1; break
        fi
        if (( _rc == 0 )); then
            if [[ "$SIMULATION" == "true" ]]; then
                printf '  %s◌  simulée%s\n' "$C_SIM" "$C0"; ITERS+=("sim|simulee|${EXP_LABELS[$_i]}")
            else
                printf '  %s●  terminée%s %sen %s%s\n' "$C_OK" "$C0" "$ESTOMPE" "$(duree "$DUREE_S")" "$C0"; ITERS+=("ok|$(duree "$DUREE_S")|${EXP_LABELS[$_i]}")
            fi
            G_OK=$(( G_OK + 1 )); continue
        fi

        printf '  %s✗  échec%s %s— code %d, %s%s\n' "$C_KO" "$C0" "$ESTOMPE" "$_rc" "$(duree "$DUREE_S")" "$C0"
        G_KO=$(( G_KO + 1 )); G_RC=$_rc; ITERS+=("ko|code $_rc|${EXP_LABELS[$_i]}")
        (( F_CONTINU )) && { info "(étape marquée « continu » : on poursuit)"; continue; }
        (( F_STOP ))    && { erreur "étape marquée « stop » : arrêt du script."; G_ARRET=2; break; }
        (( _ign ))   && continue
        if (( _rep )); then
            menu "Entrée=continuer" "t=continuer sans redemander" "n=arrêter la boucle" "q=quitter"
            _choix=""; lire "$(invite)" _choix
            case "${_choix,,}" in t) _ign=1 ;; n) G_ARRET=1; break ;; q) G_ARRET=2; break ;; esac
        else
            demander_oui_non "  Continuer quand même ? ${ESTOMPE}[O/n]${C0} " || G_ARRET=2
        fi
    done
    G_DUREE=$(( SECONDS - _debut ))
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
au_revoir() { restaurer_terminal; recap; }
trap au_revoir EXIT

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
        printf '%s%s%s%s %s %s  %s%s%s\n' "$(repeter ' ' $(( LARG_NUM + 4 )))" "$ESTOMPE" "$( (( i == n - 1 && caches == 0 )) && printf '└─' || printf '├─')" "$C0" \
               "$(glyphe "$e")" "$(pad_droite "$t" $(( $(colonne_titre) - 3 )))" "$ESTOMPE" "$d" "$C0"
    done
    (( caches > 0 )) && printf '%s%s└─ … et %d itération%s réussie%s%s\n' "$(repeter ' ' $(( LARG_NUM + 4 )))" "$ESTOMPE" "$caches" "$(pluriel "$caches")" "$(pluriel "$caches")" "$C0"
    return 0
}

ecrire_rapport() {
    [[ -d "${DIR_LOGS:-}" ]] || return 0
    local f="$DIR_LOGS/${PREFIX}_rapport.txt" l num e d t ligne
    {
        printf 'Rapport %s\n  sujet      %s\n' "$NOM_SCRIPT" "$SUJET"
        for l in ${DETAILS[@]+"${DETAILS[@]}"}; do
            if [[ "$l" == *=* ]]; then printf '  %-10s %s\n' "${l%%=*}" "${l#*=}"; else printf '  %s\n' "$l"; fi
        done
        printf '  par        %s%s sur %s\n' "$OPERATEUR" "$( (( EUID == 0 )) && printf ' (root)')" "$(hostname 2>/dev/null || printf '?')"
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
    titre_nu="${e%%|*}"; titre_nu="${titre_nu//[[:space:]]/}"
    [[ -n "$titre_nu" ]] || { erreur "titre vide :"; printf '  %s\n' "$e" >&2; exit 1; }
    analyser_validation "${reste%%|*}" || { erreur "validation « ${reste%%|*} » : $MSG_VALIDATION"; printf '  %s\n' "$e" >&2; exit 1; }
done
charger_listes
scanner_placeholders

etape_retenue() {   # <n> : passe --only et --from ?
    local m
    (( DEPUIS > 0 && $1 < DEPUIS )) && return 1
    [[ -n "$FILTRE_ETAPES" ]] || return 0
    for m in "${_morceaux[@]}"; do
        if [[ "$m" == *-* ]]; then (( $1 >= 10#${m%-*} && $1 <= 10#${m#*-} )) && return 0
        else (( $1 == 10#$m )) && return 0; fi
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
    printf '\n  %s--var nom=valeur répond à une [[question]], --list nom=a,b fige une {{liste}}%s\n\n' "$ESTOMPE" "$C0"
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
    [[ "$p" == *=* && "$nom" =~ ^[a-zA-Z0-9_]+$ && -n "$val" ]] || { erreur "--list attend nom=v1,v2 : $p"; exit 1; }
    connu_dans "$nom" ${PH_LISTES[@]+"${PH_LISTES[@]}"} || { erreur "aucune liste « $nom » utilisée (voir --vars)"; exit 1; }
    LISTE_FIGEE["$nom"]="${val//,/$'\n'}"
done

if [[ "$LISTER_ETAPES" == "true" ]]; then plan_initial oui; printf '\n'; exit 0; fi

# En simulation, un contrôle qui échoue n'empêche pas de voir le plan.
if ! verifier; then [[ "$SIMULATION" == "true" ]] && attention "contrôles en échec — simulation quand même" || exit 1; fi
[[ "$INTERACTIF" == "non" && "$SANS_QUESTION" != "true" ]] && attention "aucun terminal : les réponses seront lues sur l'entrée standard (-y pour ne rien demander)"
MANQUANTS=""; for b in "${REQUIS[@]}"; do command -v "$b" >/dev/null 2>&1 || MANQUANTS+=" $b"; done
[[ -n "$MANQUANTS" ]] && attention "binaires absents :$MANQUANTS"

# sudo demande son mot de passe sur le terminal, au moment où la commande
# part — donc au milieu du déroulé. Avec -y, personne n'est là pour
# répondre et le script attendrait indéfiniment.
if (( EUID != 0 )) && printf '%s\n' "${COMMANDES[@]}" ${LISTES[@]+"${LISTES[@]}"} | grep -qw sudo; then
    if [[ "$SANS_QUESTION" == "true" ]]; then
        attention "des étapes utilisent sudo : lancez « sudo -v » avant, sinon -y restera bloqué sur la demande de mot de passe"
    else
        info "des étapes utilisent sudo : le mot de passe sera demandé au moment voulu"
    fi
fi

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
for l in ${DETAILS[@]+"${DETAILS[@]}"}; do
    if [[ "$l" == *=* ]]; then entete "${l%%=*}" "${l#*=}"; else info "$l"; fi
done
entete "sortie"   "${DIR_LOGS%/*}$( (( CREES > 0 )) && printf '  (%d dossier%s créé%s)' "$CREES" "$(pluriel "$CREES")" "$(pluriel "$CREES")")"
entete "par"      "$OPERATEUR$( (( EUID == 0 )) && printf ' (root)')"
entete "journal"  "$LOG"
[[ -n "$CONF" ]]                 && entete "config"     "$CONF"
[[ "$SIMULATION" == "true" ]]    && entete "dry-run"    "rien ne sera exécuté"
[[ "$SANS_QUESTION" == "true" ]] && entete "-y"         "aucune question ne sera posée"
[[ "$TOUT_VALIDER" == "true" ]]  && entete "-a"         "chaque étape sera confirmée"
[[ "$REPRENDRE" == "true" ]]     && entete "resume"     "les étapes déjà réussies seront sautées"
[[ -n "$FILTRE_ETAPES" ]]        && entete "only"       "étapes $FILTRE_ETAPES"
(( DEPUIS > 0 ))                 && entete "from"       "étape $DEPUIS"
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

    # Deux étapes identiques ont deux clés : sinon l'échec de la seconde
    # serait masqué par la réussite de la première au prochain --resume.
    OCC=0; for e in "${COMMANDES[@]:0:NUM-1}"; do [[ "$e" == "$entree" ]] && OCC=$(( OCC + 1 )); done
    CLE="$(empreinte "$TITRE|$BRUTE|$OCC")"
    if deja_faite "$CLE"; then
        titre_etape "$NUM" "$TOTAL" "$TITRE"; info "déjà réussie précédemment — sautée (--resume)"
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
            ETAPE_PASSEE=0          # un « p » donné pendant une édition annulée ne compte plus
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
                info "vérifiez la commande de liste (--vars), ou figez-la avec --list"
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

        NB_ITER=${#EXP_CMDS[@]}; REPETEE=0
        [[ $NB_ITER -gt 1 || -n "${EXP_LABELS[0]}" ]] && REPETEE=1
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
            ""|o|oui|y|yes|u|t)
                UNE_PAR_UNE=0; [[ "${CHOIX,,}" == "u" ]] && UNE_PAR_UNE=1
                executer_groupe "$UNE_PAR_UNE" "$REPETEE"
                (( REPETEE && ${#ITERS[@]} > 0 )) && ENFANTS["$NUM"]="$(printf '%s\x01' "${ITERS[@]}")"

                if (( REPETEE )); then
                    if [[ "$SIMULATION" == "true" ]]; then RECAP+=("$NUM|sim|$NB_ITER iter|$TITRE")
                    elif (( G_KO == 0 && G_INT == 0 && G_SKIP == 0 )); then
                        RECAP+=("$NUM|ok|$G_OK/$NB_ITER$( (( EXP_TRONQUE )) && printf ' tronq') $(duree "$G_DUREE")|$TITRE"); NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"
                    elif (( G_KO > 0 )); then RECAP+=("$NUM|ko|$G_KO KO /$NB_ITER|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                    else RECAP+=("$NUM|int|$G_OK/$NB_ITER ok|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 )); fi
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
            q) quitter ;;
            *) printf '  %s« %s » n'"'"'est pas une réponse attendue%s\n' "$JAUNE" "$CHOIX" "$C0" ;;
        esac
    done
done

if (( NB_FILTREES == TOTAL )); then
    attention "aucune étape retenue : --only / --from les écartent toutes"
elif (( NB_FILTREES > 0 )); then
    info "$NB_FILTREES étape(s) écartée(s) par --only / --from"
fi
(( NB_KO > 0 )) && exit 1
exit 0
