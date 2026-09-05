#!/usr/bin/env bash
#
# forensic.sh — enchaîne des commandes forensiques, validées une à une.
#               Aide complète :  ./forensic.sh -h
#
#   section 1  les variables : la seule chose à changer entre deux analyses
#   section 2  les commandes et les listes
#   section 3  vos fonctions métier
#   section 4  la mécanique, que vous n'avez pas besoin de lire
#
# On veut gérer les échecs nous-mêmes, donc pas de -e.
#   -u        : une variable oubliée devient une erreur, pas une chaîne vide
#   pipefail  : "cmd | tee f" remonte l'échec de cmd, que tee masquerait
set -uo pipefail

# Tableaux associatifs, ${var,,} : il faut bash 4. Le test vient avant tout
# le reste, sinon l'utilisateur reçoit une erreur de syntaxe incompréhensible.
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] \
   || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]; }; then
    printf 'ERREUR : bash 4.3 ou plus est requis (trouvé : %s).\n' "${BASH_VERSION:-inconnu}" >&2
    printf 'Sur macOS :  brew install bash  puis  /opt/homebrew/bin/bash forensic.sh\n' >&2
    exit 1
fi


# =====================================================================
# 1. VARIABLES — les seules valeurs à changer entre deux analyses
#
# Tout ce qui est ici peut aussi venir d'un fichier de configuration
# (-c poste.conf) ou de la ligne de commande (--image, --pc, --salle...),
# ce qui évite de modifier le script pour chaque poste.
# Priorité :  valeurs ci-dessous  <  fichier -c  <  options de la ligne
# =====================================================================
IMAGE="/images/pc07.dd"       # image disque à analyser
PC="PC07"                     # poste
SALLE="B204"                  # salle
OS="windows"                  # windows ou linux
BASE="/cases"                 # racine où tout est écrit
OPERATEUR="${USER:-inconnu}"  # noté dans le journal et le rapport

# Fuseau utilisé par mactime pour AFFICHER les dates. Mettez celui du
# poste analysé, pas le vôtre, sinon la timeline ne correspondra ni aux
# journaux applicatifs ni aux témoignages. Toujours un nom de zone, jamais
# un décalage fixe type UTC+1, qui serait faux la moitié de l'année.
# Travailler en UTC est aussi un choix défendable si vous croisez
# plusieurs machines : les sources restent alors comparables entre elles.
TZ_MACTIME="Europe/Paris"

# Validation de TOUTES les étapes, y compris celles marquées false.
# Se règle ici, ou ponctuellement avec l'argument -v.
TOUT_VALIDER="false"

# Binaires attendus. Absence = simple avertissement, car vous pouvez
# vouloir ne lancer qu'une partie des étapes.
REQUIS=(mmls fls ils icat mactime testdisk photorec)

# Garde-fou : au-delà de ce nombre d'itérations, une étape {{liste}}
# demande confirmation avant de partir pour la nuit.
MAX_ITERATIONS=500

# Les chemins de travail sont dérivés des variables ci-dessus. Cette
# fonction est rappelée après lecture de -c et des options, pour que les
# chemins suivent toujours la dernière valeur de PC, SALLE, OS et BASE.
#
# Toute variable nommée DIR_quelquechose est vue comme un dossier de
# travail : le script la vérifie et la crée au besoin.
calculer_chemins() {
    DEST="$BASE/$SALLE/$OS/$PC"
    PREFIX="${PC}_${SALLE}_${OS}"

    DIR_BODY="$DEST/body"
    DIR_TIMELINE="$DEST/timeline"
    DIR_CARVING="$DEST/carving"
    DIR_LOGS="$DEST/logs"
}


# =====================================================================
# 2. COMMANDES ET LISTES
#
# Tout est dans la fonction ci-dessous, pour une seule raison : les
# $VARIABLES y sont remplacées APRÈS la lecture du fichier -c et des
# options. Vous l'éditez comme un simple tableau, sans y penser.
#
# ---------------------------------------------------------------------
# FORMAT D'UNE ÉTAPE :  "Titre|validation|commande"
#
#   validation = true   attend votre accord avant de lancer
#                false  affiche puis lance directement
#   On peut y ajouter des options, séparées par des virgules :
#                log       enregistre la sortie de la commande au journal
#                          (à éviter pour une commande interactive, qui
#                           perdrait son terminal : voir photorec)
#                stop      un échec arrête le script sans rien demander
#                continu   un échec est ignoré sans rien demander
#   Exemples :   "Titre|true|..."   "Titre|false,log|..."   "Titre|true,continu|..."
#
# ---------------------------------------------------------------------
# TROIS FAÇONS D'INSÉRER UNE VALEUR
#
#   $VARIABLE   connue à l'avance : remplacée au lancement du script.
#
#   [[nom]]     UNE valeur inconnue à l'avance : demandée quand on arrive
#               sur l'étape, puis réutilisée dans toutes les commandes
#               suivantes qui contiennent le même [[nom]].
#               Si LISTES contient une entrée du même nom, la question
#               devient un menu numéroté au lieu d'une saisie à l'aveugle.
#
#   {{nom}}     PLUSIEURS valeurs : l'étape est répétée une fois par
#               valeur. Les valeurs viennent de LISTES, plus bas.
#               Entourez toujours un {{nom}} d'apostrophes — '{{fichier}}' —
#               car les valeurs contiennent des espaces.
#
#               Deux {{listes}} dans une même commande s'emboîtent, de
#               gauche à droite : la seconde est régénérée pour chaque
#               valeur de la première.
#
#               Et si une liste en appelle une autre (la liste "fichier"
#               a besoin de {{home}} pour savoir où chercher), vous
#               n'écrivez que celle qui vous intéresse : le script
#               remonte la chaîne et boucle d'abord sur les homes.
#               '{{fichier}}' seul parcourt donc bien tous les fichiers
#               de tous les profils.
#
#               Chaque valeur peut avoir un libellé lisible ; il est
#               toujours disponible sous le nom {{nom_libelle}}.
#               Pour "home", {{home}} vaut l'inode et {{home_libelle}}
#               le chemin du profil.
#
# ---------------------------------------------------------------------
# LE PIÈGE : QUAND ÉCHAPPER LE $
#   Le tableau est entre guillemets doubles, donc un $ est remplacé
#   MAINTENANT, à la lecture du tableau. C'est voulu pour $IMAGE ou
#   $DIR_BODY, qui existent déjà. Mais une variable née PENDANT la
#   commande n'existe pas encore, et set -u arrête tout.
#
#     FAUX   "Boucle|true|for u in a b; do echo home_$u; done"
#            -> u: unbound variable
#
#     JUSTE  "Boucle|true|for u in a b; do echo home_\$u; done"
#            -> le \$ protège u jusqu'à l'exécution
#
#   Même chose pour $1, $(date), $?, $! : échappez-les avec \.
#     "Horodatage|true|echo debut \$(date +%H:%M) >> '$DIR_LOGS/t.txt'"
#
# ---------------------------------------------------------------------
# CE QUI EST ACCEPTÉ
#   Tout passe par eval, donc la syntaxe shell complète fonctionne :
#     redirections   "... > '$DIR_BODY/sortie.txt'"
#     tubes          "... | tee '$DIR_LOGS/vu.txt' | tail -n 20"
#     conditions     "if [ -f '$IMAGE' ]; then echo ok; else echo non; fi"
#     ET / OU        "[ -f '$IMAGE' ] && echo present || echo absent"
#   Les tests [[ ... ]] ne sont jamais confondus avec un [[placeholder]],
#   car un placeholder ne contient ni espace ni tiret.
#
# ---------------------------------------------------------------------
# LIMITES
#   Pas de | dans le titre ni dans le champ validation : seuls les deux
#   premiers | séparent les champs. Écrivez "fls et ils", pas "fls | ils".
#   Le | reste libre dans la commande elle-même.
#
#   tail après un tee, oui ; head, non : head ferme le tube, la commande
#   amont meurt d'un SIGPIPE et l'étape est comptée en échec (code 141).
#
#   Ne mettez jamais une commande interactive dans un tube, ni avec
#   l'option log : photorec perdrait son terminal.
#
#   Au-delà de deux ou trois instructions, écrivez une fonction en
#   section 3 et appelez-la ici. Plus d'échappements à gérer, la ligne
#   reste lisible à l'affichage, et vous pouvez y placer le garde-fou
#   d'interruption.
# =====================================================================
definir_commandes() {

COMMANDES=(

# mmls affiche la table des partitions. L'offset réclamé par les étapes
# suivantes se lit dans sa 3e colonne — mais [[offset]] le propose en
# menu, donc vous n'avez rien à recopier.
"Table des partitions|true,log|mmls '$IMAGE'"

# Fichiers alloués ET supprimés encore référencés, au format body.
"Fichiers alloués et supprimés|true|fls -r -p -m / -o [[offset]] '$IMAGE' > '$DIR_BODY/${PREFIX}_fls.body'"

# Inodes non alloués, souvent en échec sur NTFS : l'étape est alors à passer.
"Inodes non alloués|true,continu|ils -m -o [[offset]] '$IMAGE' > '$DIR_BODY/${PREFIX}_ils.body'"

# Simple concaténation, sans risque : pas de validation demandée.
# cat sur un fichier manquant échouerait ; on ne prend que ceux qui existent.
"Fusion des body files|false|fusionner_body '$DIR_BODY/${PREFIX}_full.body' '$DIR_BODY/${PREFIX}_fls.body' '$DIR_BODY/${PREFIX}_ils.body'"

# mactime convertit le body fusionné en timeline CSV lisible.
"Timeline|true|mactime -b '$DIR_BODY/${PREFIX}_full.body' -z '$TZ_MACTIME' -d -y > '$DIR_TIMELINE/${PREFIX}_timeline.csv'"

# --- Exemple d'étape répétée -----------------------------------------
# {{home}} vaut tour à tour chaque profil utilisateur trouvé par la
# liste "home" définie plus bas : l'étape est jouée une fois par profil.
"Inventaire par utilisateur|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' '{{home_libelle}}' '$DIR_BODY'"

# Deux listes dans la même commande = boucles imbriquées : pour chaque
# home, chacun de ses fichiers. Décommentez pour l'essayer — pensez à
# regarder le nombre d'itérations annoncé avant de valider.
#"Hachage fichier par fichier|true|hacher_fichier '$IMAGE' '[[offset]]' '{{fichier}}' '{{fichier_libelle}}' >> '$DIR_LOGS/${PREFIX}_hashes.txt'"

# La numérotation de testdisk est celle qu'attend photorec juste après.
"Liste des partitions (testdisk)|true,log|testdisk /list '$IMAGE'"

# freespace = espace non alloué seulement. search doit rester en dernier.
# Pas d'option log : photorec a besoin de son terminal.
"Carving|true|photorec /log /logname '$DIR_LOGS/${PREFIX}_photorec.log' /d '$DIR_CARVING/recup_' /cmd '$IMAGE' [[index_testdisk]],fileopt,everything,enable,freespace,search"

# --- Autres exemples prêts à décommenter -----------------------------
# Garder la sortie ET la voir, sans noyer le terminal :
#"Table des partitions|true|mmls '$IMAGE' | tee '$DIR_LOGS/mmls.txt' | tail -n 20"
#
# Ne lancer une étape que si le fichier attendu est là :
#"Timeline|true|if [ -s '$DIR_BODY/${PREFIX}_full.body' ]; then mactime -b '$DIR_BODY/${PREFIX}_full.body' -z '$TZ_MACTIME' -d -y > '$DIR_TIMELINE/${PREFIX}_timeline.csv'; else echo 'body vide, rien a faire'; fi"
#
# Boucle shell classique : le \$f est échappé, il n'existe qu'à
# l'exécution. Le test [ -e ] évite l'erreur si aucun fichier ne
# correspond au motif. (Une liste {{...}} est en général plus lisible.)
#"Hachage des sorties|true|for f in '$DIR_BODY'/*.body; do [ -e \"\$f\" ] || continue; sha256sum \"\$f\"; done > '$DIR_LOGS/${PREFIX}_hashes.txt'"

)

# ---------------------------------------------------------------------
# LISTES — d'où viennent les valeurs des {{nom}} et les menus des [[nom]]
#
#   Format :  "nom|commande qui écrit une valeur par ligne"
#
#   Une ligne peut porter un libellé, séparé par une TABULATION :
#       2048<TAB>NTFS 40 Go
#   Seule la partie avant la tabulation entre dans la commande ; le
#   libellé sert à l'affichage. C'est ce qui permet à [[offset]] de
#   montrer "2048   NTFS 40 Go" tout en n'insérant que 2048.
#
#   Une commande de liste peut contenir [[nom]] et {{nom}} : c'est ce
#   qui rend l'emboîtement possible. La liste "fichier" ci-dessous
#   dépend de {{home}} : elle est donc régénérée pour chaque home.
#
#   Les listes sont mises en cache : mmls n'est lancé qu'une fois, même
#   s'il sert au menu de [[offset]] et à une étape répétée.
#
#   Les lignes vides sont ignorées. Si la commande échoue ou ne renvoie
#   rien, le script vous le dit et vous laisse la main.
# ---------------------------------------------------------------------
LISTES=(

# Menu de [[offset]] : les partitions de l'image, l'espace non alloué en moins.
"offset|lister_partitions '$IMAGE'"

# Menu de [[index_testdisk]] : la numérotation attendue par photorec.
"index_testdisk|lister_partitions_testdisk '$IMAGE'"

# Les profils utilisateurs. La valeur est l'inode (ce que fls attend),
# le libellé est le chemin (ce que vous voulez lire).
"home|lister_homes '$IMAGE' '[[offset]]' '$OS'"

# Les fichiers d'un home. Dépend de {{home}} : emboîtement automatique.
"fichier|lister_fichiers '$IMAGE' '[[offset]]' '{{home}}'"

)
}


# =====================================================================
# 3. FONCTIONS MÉTIER — les traitements longs, appelés depuis la section 2
#
# Une fonction définie ici s'appelle comme une commande dans COMMANDES
# ou dans LISTES :
#     "Inventaire|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' ..."
# Les arguments, les [[valeurs]] et les {{listes}} fonctionnent normalement.
#
# Pour reprendre une fonction venue d'un autre script :
#   - remplacer les "exit" par "return" (exit tuerait tout le script)
#   - terminer par un "return" explicite : ce code devient ✅ ou ❌
#   - déclarer les variables internes en "local"
#   - dans toute boucle longue, ajouter en première ligne :
#         (( INTERROMPU )) && return 130
#     sans quoi Ctrl-C tue l'itération en cours mais pas la boucle
#   - attention à set -u : une variable non définie arrête le script,
#     ce que l'autre script tolérait peut-être
#
# Une fonction de LISTE écrit une valeur par ligne sur sa sortie
# standard, éventuellement suivie d'une TABULATION et d'un libellé.
# Ses messages d'erreur vont sur la sortie d'erreur (>&2), sinon ils
# seraient pris pour des valeurs.
# =====================================================================

# --- Partitions -------------------------------------------------------

# lister_partitions <image>
# Alimente le menu de [[offset]] : valeur = offset en secteurs,
# libellé = type de partition et taille.
lister_partitions() {
    local img="$1"
    mmls "$img" 2>/dev/null | awk '
        /Units are in/ { for (i=1; i<=NF; i++) if ($i ~ /-byte/) { split($i, u, "-"); unite = u[1] } }
        $1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9]+:[0-9]+$/ {
            desc = $6
            for (i = 7; i <= NF; i++) desc = desc " " $i
            if (desc ~ /^Unallocated/) next
            if (unite == "") unite = 512
            octets = $5 * unite
            if      (octets >= 1073741824) taille = sprintf("%.1f Go", octets / 1073741824)
            else if (octets >= 1048576)    taille = sprintf("%.1f Mo", octets / 1048576)
            else                           taille = sprintf("%d o", octets)
            printf "%d\t%s — %s\n", $3 + 0, desc, taille
        }'
    return "${PIPESTATUS[0]}"
}

# lister_partitions_testdisk <image>
# Alimente le menu de [[index_testdisk]] : photorec veut le NUMÉRO de
# partition tel que testdisk le donne, pas l'offset en secteurs.
lister_partitions_testdisk() {
    local img="$1"
    testdisk /list "$img" 2>/dev/null | awk '
        $1 ~ /^[0-9]+$/ && $2 ~ /^[PLED*]$/ {
            desc = $3
            for (i = 4; i <= NF; i++) desc = desc " " $i
            printf "%d\t%s\n", $1, desc
        }'
    return "${PIPESTATUS[0]}"
}

# --- Profils utilisateurs ---------------------------------------------

# lister_homes <image> <offset> <os>
# Valeur = inode du profil (ce que fls attend), libellé = son chemin.
# Dans une commande, '{{home}}' donne l'inode et '{{home_libelle}}' le
# chemin : tout libellé est ainsi disponible sous le nom <liste>_libelle.
lister_homes() {
    local img="$1" off="$2" ossys="$3"
    local racine ino

    case "${ossys,,}" in
        windows|win) racine="Users" ;;
        *)           racine="home"  ;;
    esac

    # Inode du dossier racine des profils, cherché sans tenir compte de
    # la casse : NTFS écrit "Users", certaines images "USERS".
    ino=$(fls -o "$off" -D -p "$img" 2>/dev/null | awk -F'\t' -v r="$racine" '
        { nom = $2; sub(/^.*\//, "", nom)
          if (tolower(nom) == tolower(r)) { split($1, c, " "); n = c[length(c)]; sub(/:$/, "", n); print n; exit } }')

    if [[ -z "$ino" ]]; then
        printf 'aucun dossier "%s" à la racine de la partition %s\n' "$racine" "$off" >&2
        return 1
    fi

    # Les profils système ne sont presque jamais ce qu'on cherche ; ils
    # restent listés mais en fin de liste serait un raffinement inutile,
    # on les écarte simplement. Retirez la ligne si vous les voulez.
    fls -o "$off" -D -p "$img" "$ino" 2>/dev/null | awk -F'\t' '
        {
            chemin = $2
            nom = chemin; sub(/^.*\//, "", nom)
            if (nom == "." || nom == "..") next
            if (nom ~ /^\$/) next
            if (tolower(nom) ~ /^(all users|default|default user|public|desktop\.ini)$/) next
            split($1, c, " "); n = c[length(c)]; sub(/:$/, "", n)
            supprime = ($1 ~ /\*/) ? " (supprimé)" : ""
            printf "%s\t%s%s\n", n, chemin, supprime
        }'
    return 0
}

# lister_fichiers <image> <offset> <inode_du_home>
# Les fichiers d'un profil, récursivement. Valeur = inode,
# libellé = chemin. C'est la liste qui, combinée à {{home}}, donne
# "tous les fichiers de tous les profils".
lister_fichiers() {
    local img="$1" off="$2" ino="$3"
    fls -o "$off" -F -p -r "$img" "$ino" 2>/dev/null | awk -F'\t' '
        {
            split($1, c, " "); n = c[length(c)]; sub(/:$/, "", n)
            if (n == "" || n !~ /^[0-9]/) next
            supprime = ($1 ~ /\*/) ? " (supprimé)" : ""
            printf "%s\t%s%s\n", n, $2, supprime
        }'
    return 0
}

# --- Traitements ------------------------------------------------------

# fusionner_body <sortie> <entrée> [entrée...]
# cat échouerait sur un fichier absent ; ici l'absence est normale
# (ils échoue souvent sur NTFS) et ne doit pas casser la chaîne.
fusionner_body() {
    local sortie="$1"; shift
    local f
    local -a presents=()

    for f in "$@"; do
        if [[ -s "$f" ]]; then
            presents+=("$f")
        else
            printf '  (ignoré, vide ou absent : %s)\n' "$f"
        fi
    done

    if (( ${#presents[@]} == 0 )); then
        printf 'aucun body file à fusionner\n' >&2
        return 1
    fi

    cat "${presents[@]}" > "$sortie" || return 1
    local n; n=$(wc -l < "$sortie" | tr -d ' ')
    printf '  %s ligne%s -> %s\n' "$n" "$(pluriel "$n")" "$sortie"
    return 0
}

# inventorier_home <image> <offset> <inode> <chemin> <dir_body>
# Un body file par profil : on voit tout de suite quel utilisateur a
# fait quoi, sans filtrer la timeline complète.
inventorier_home() {
    local img="$1" off="$2" ino="$3" chemin="$4" dest="$5"
    local nom sortie

    nom=$(nettoyer_nom "$chemin")
    sortie="$dest/home_${nom}.body"

    fls -r -p -m "/$chemin" -o "$off" "$img" "$ino" > "$sortie" || return 1
    local n; n=$(wc -l < "$sortie" | tr -d ' ')
    printf '  %s entrée%s -> %s\n' "$n" "$(pluriel "$n")" "$sortie"
    return 0
}

# hacher_fichier <image> <offset> <inode> <chemin>
# Exemple d'étape doublement imbriquée : appelée pour chaque fichier de
# chaque profil. Le garde-fou d'interruption n'est pas utile ici (pas de
# boucle interne), mais l'appelant, lui, vérifie entre deux itérations.
hacher_fichier() {
    local img="$1" off="$2" ino="$3" chemin="$4"
    local somme
    somme=$(icat -o "$off" "$img" "$ino" 2>/dev/null | sha256sum | cut -d' ' -f1) || return 1
    printf '%s  %s\n' "$somme" "$chemin"
    return 0
}

# nettoyer_nom <texte> : de quoi fabriquer un nom de fichier sûr à
# partir d'un chemin ou d'un libellé quelconque.
nettoyer_nom() {
    local s="$1"
    s="${s//\//_}"
    s="${s// /_}"
    s="${s//[^A-Za-z0-9._-]/}"
    printf '%s' "${s:-sans_nom}"
}


# =====================================================================
# 4. MÉCANIQUE — à ne pas modifier pour un usage courant
# =====================================================================

# --- Couleurs et largeur du terminal ---------------------------------
# La couleur est un confort, jamais une information : chaque symbole
# (✅ ❌ ⏭️) reste lisible sans elle, dans un pipe ou un fichier de log.
COULEUR="auto"          # auto, oui, non — réglable par --couleur
LARGEUR=80

init_affichage() {
    local actif="non"
    case "$COULEUR" in
        oui)  actif="oui" ;;
        non)  actif="non" ;;
        auto) [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]] && actif="oui" ;;
    esac

    if [[ "$actif" == "oui" ]]; then
        C0=$'\033[0m';    GRAS=$'\033[1m';   ESTOMPE=$'\033[2m'
        ROUGE=$'\033[31m'; VERT=$'\033[32m'; JAUNE=$'\033[33m'
        BLEU=$'\033[34m';  CYAN=$'\033[36m'; MAGENTA=$'\033[35m'
    else
        C0=""; GRAS=""; ESTOMPE=""
        ROUGE=""; VERT=""; JAUNE=""; BLEU=""; CYAN=""; MAGENTA=""
    fi

    # tput peut manquer ou échouer (cron, terminal inconnu) : on retombe
    # sur 80 colonnes, et on borne pour éviter les lignes absurdes.
    if [[ -t 1 ]]; then
        LARGEUR=$(tput cols 2>/dev/null || printf 80)
    else
        LARGEUR=80
    fi
    [[ "$LARGEUR" =~ ^[0-9]+$ ]] || LARGEUR=80
    (( LARGEUR < 40 ))  && LARGEUR=40
    (( LARGEUR > 100 )) && LARGEUR=100
}

# repeter <motif> <n>
repeter() {
    local i s=""
    for (( i = 0; i < $2; i++ )); do s+="$1"; done
    printf '%s' "$s"
}

# regle [couleur] : un trait sur toute la largeur
regle() {
    printf '%s%s%s\n' "${1:-$ESTOMPE}" "$(repeter '─' "$LARGEUR")" "$C0"
}

# barre <fait> <total> : petite jauge de progression
barre() {
    local fait="$1" total="$2" larg=12 plein
    (( total > 0 )) || total=1
    plein=$(( fait * larg / total ))
    (( plein > larg )) && plein=$larg
    printf '%s%s%s%s%s' "$VERT" "$(repeter '━' "$plein")" "$ESTOMPE" "$(repeter '━' $(( larg - plein )))" "$C0"
}

# entete <clé> <valeur> : ligne alignée du bandeau de démarrage.
# La clé est en ASCII, et pas par hasard : sous une locale C, printf
# compte les octets, et un « é » décalerait toute la colonne. Partout où
# une largeur est imposée (%-10s, %-8s...), le texte reste sans accent ;
# les libellés accentués, eux, sont toujours rejetés en fin de ligne.
entete() {
    printf '  %s%-10s%s %s\n' "$ESTOMPE" "$1" "$C0" "$2"
}

# info / attention / erreur : trois niveaux, toujours préfixés
info()      { printf '  %s%s%s\n'        "$ESTOMPE" "$*" "$C0"; }
attention() { printf '  %s⚠  %s%s\n'     "$JAUNE"   "$*" "$C0"; }
erreur()    { printf '%s✖  %s%s\n'       "$ROUGE"   "$*" "$C0" >&2; }

# pluriel <n> : le « s » qui va bien, pour ne pas écrire "1 fichiers"
pluriel() { (( $1 > 1 )) && printf 's'; return 0; }

# duree <secondes> : "42s", "3m07s" ou "1h04m"
duree() {
    local s="$1"
    if   (( s < 60 ));   then printf '%ds' "$s"
    elif (( s < 3600 )); then printf '%dm%02ds' $(( s / 60 )) $(( s % 60 ))
    else                      printf '%dh%02dm' $(( s / 3600 )) $(( s % 3600 / 60 ))
    fi
}


# --- Aide ------------------------------------------------------------
aide() {
    cat <<'FIN_AIDE'
---------------------------------------------------------------------
 forensic.sh — enchaîne des commandes forensiques, validées une à une
---------------------------------------------------------------------

 UTILISATION
     ./forensic.sh                     suit le champ validation des étapes
     ./forensic.sh -v                  demande confirmation à CHAQUE étape
     ./forensic.sh -y                  ne demande jamais rien (attention)
     ./forensic.sh -n                  simulation : affiche sans exécuter
                                       (les commandes de LISTES, elles,
                                        sont lancées : c'est ce qui permet
                                        d'annoncer le nombre d'itérations)
     ./forensic.sh --etapes            montre le plan et s'arrête
     ./forensic.sh --seulement 2,5-7   ne joue que ces étapes
     ./forensic.sh --depuis 4          reprend à partir de l'étape 4
     ./forensic.sh --reprendre         saute les étapes déjà réussies
     ./forensic.sh --sans-couleur      sortie sans code couleur
     Les options se combinent.
     Code de sortie : 0 si tout est passé, 1 s'il reste un échec.

 VALEURS À FOURNIR
     ./forensic.sh --vars              liste les [[valeurs]] et {{listes}}
     ./forensic.sh --var offset=2048   fournit une [[valeur]] à l'avance
     ./forensic.sh --liste home=41,52  fige une {{liste}} sur ces valeurs
     --var et --liste sont répétables.

 CONFIGURATION SANS TOUCHER AU SCRIPT
     ./forensic.sh -c postes/pc07.conf
     Le fichier contient de simples affectations :
         IMAGE="/images/pc07.dd"
         PC="PC07" ; SALLE="B204" ; OS="windows"
     Les options --image --pc --salle --os --base --tz --operateur
     l'emportent sur le fichier, qui l'emporte sur la section 1.

 À CHAQUE ÉTAPE
     Entrée  exécuter        p  passer cette étape
     e       éditer la ligne r  ressaisir les [[valeurs]] de l'étape
     s       voir la commande en clair sur plusieurs lignes
     q       arrêter le script
     Sur une étape répétée s'ajoutent :
     u       exécuter une itération à la fois (validation de chacune)
     l       lister les itérations prévues
     Ctrl-C pendant une commande l'interrompt sans tuer le script :
     il vous demande si vous continuez avec l'étape suivante.

 AJOUTER UNE ÉTAPE
     Une ligne dans le tableau COMMANDES, au format :
         "Titre|validation|commande"
     validation = true  -> attend votre accord avant de lancer
                  false -> affiche puis lance directement
     et, après une virgule, des options :
                  log      -> la sortie est copiée dans le journal
                  stop     -> un échec arrête tout, sans question
                  continu  -> un échec est ignoré, sans question
     Une étape false ne peut pas être passée : pour reprendre la main
     sur toutes les étapes, lancez ./forensic.sh -v
     Le découpage se fait sur les deux premiers | uniquement,
     les pipes de la commande elle-même sont donc préservés.

 DOSSIERS
     Toute variable nommée DIR_quelquechose est vue comme un dossier :
     le script vérifie sa présence et le crée au besoin, puis vous
     l'utilisez normalement dans les commandes ($DIR_BODY, etc.).

 TROIS FAÇONS D'INSÉRER UNE VALEUR
     $VARIABLE   connue à l'avance, remplacée au lancement du script
     [[nom]]     UNE valeur, demandée quand on arrive sur l'étape puis
                 RÉUTILISÉE dans toutes les étapes suivantes qui
                 contiennent le même [[nom]]. Si le tableau LISTES
                 contient une entrée du même nom, la question devient
                 un menu numéroté.
                 Exemple : [[offset]] est saisi une fois, servi à fls
                 et à ils, et proposé à partir de la sortie de mmls.
     {{nom}}     PLUSIEURS valeurs : l'étape est rejouée pour chacune.
                 Deux {{listes}} s'emboîtent, de gauche à droite.
                 Une liste qui en appelle une autre déclenche la boucle
                 extérieure toute seule : '{{fichier}}' parcourt les
                 fichiers de tous les profils sans que vous ayez à
                 écrire {{home}}.
                 Le libellé d'une valeur est disponible en
                 {{nom_libelle}}.

 JOURNAL ET RAPPORT
     Chaque exécution écrit :
         <sortie>/logs/<prefixe>_script.log     commandes et codes
         <sortie>/logs/<prefixe>_rapport.txt    récapitulatif final
         <sortie>/logs/<prefixe>_etat.txt       étapes réussies (--reprendre)

 À SAVOIR
     Les commandes passent par eval, ce qui fait fonctionner >, | et
     sudo tee. En contrepartie tout est interprété par le shell :
     n'y mettez que des commandes que vous écrivez vous-même.
FIN_AIDE
}


# --- Arguments de la ligne de commande -------------------------------
# On ne fait que collecter ici. L'application vient plus bas, dans
# l'ordre : section 1, puis fichier -c, puis options. Les commandes ne
# sont construites qu'après, pour que $DIR_BODY et compagnie soient justes.
PRESETS=()          # --var  nom=valeur
PRESETS_LISTE=()    # --liste nom=v1,v2
CONF=""
LISTER_VARS="false"
LISTER_ETAPES="false"
SIMULATION="false"
SANS_QUESTION="false"
REPRENDRE="false"
FILTRE_ETAPES=""
DEPUIS=0
declare -A OPT=()      # surcharges venues de la ligne de commande

exige_valeur() {
    [[ -n "${2:-}" ]] || { printf 'ERREUR : %s attend une valeur.\n' "$1" >&2; exit 1; }
}

while (( $# > 0 )); do
    case "$1" in
        -v|--valider)     TOUT_VALIDER="true";    shift ;;
        -y|--oui)         SANS_QUESTION="true";   shift ;;
        -n|--simulation|--dry-run)
                          SIMULATION="true";      shift ;;
        --etapes|--plan)  LISTER_ETAPES="true";   shift ;;
        --vars)           LISTER_VARS="true";     shift ;;
        --reprendre)      REPRENDRE="true";       shift ;;

        --var)            exige_valeur "$1" "${2:-}"; PRESETS+=("$2");        shift 2 ;;
        --var=*)          PRESETS+=("${1#--var=}");                           shift ;;
        --liste)          exige_valeur "$1" "${2:-}"; PRESETS_LISTE+=("$2");  shift 2 ;;
        --liste=*)        PRESETS_LISTE+=("${1#--liste=}");                   shift ;;

        --seulement)      exige_valeur "$1" "${2:-}"; FILTRE_ETAPES="$2";     shift 2 ;;
        --seulement=*)    FILTRE_ETAPES="${1#--seulement=}";                  shift ;;
        --depuis)         exige_valeur "$1" "${2:-}"; DEPUIS="$2";            shift 2 ;;
        --depuis=*)       DEPUIS="${1#--depuis=}";                            shift ;;

        -c|--conf)        exige_valeur "$1" "${2:-}"; CONF="$2";              shift 2 ;;
        --conf=*)         CONF="${1#--conf=}";                                shift ;;

        --image)          exige_valeur "$1" "${2:-}"; OPT[IMAGE]="$2";        shift 2 ;;
        --image=*)        OPT[IMAGE]="${1#--image=}";                         shift ;;
        --pc)             exige_valeur "$1" "${2:-}"; OPT[PC]="$2";           shift 2 ;;
        --pc=*)           OPT[PC]="${1#--pc=}";                               shift ;;
        --salle)          exige_valeur "$1" "${2:-}"; OPT[SALLE]="$2";        shift 2 ;;
        --salle=*)        OPT[SALLE]="${1#--salle=}";                         shift ;;
        --os)             exige_valeur "$1" "${2:-}"; OPT[OS]="$2";           shift 2 ;;
        --os=*)           OPT[OS]="${1#--os=}";                               shift ;;
        --base)           exige_valeur "$1" "${2:-}"; OPT[BASE]="$2";         shift 2 ;;
        --base=*)         OPT[BASE]="${1#--base=}";                           shift ;;
        --tz)             exige_valeur "$1" "${2:-}"; OPT[TZ_MACTIME]="$2";   shift 2 ;;
        --tz=*)           OPT[TZ_MACTIME]="${1#--tz=}";                       shift ;;
        --operateur)      exige_valeur "$1" "${2:-}"; OPT[OPERATEUR]="$2";    shift 2 ;;
        --operateur=*)    OPT[OPERATEUR]="${1#--operateur=}";                 shift ;;

        --couleur)        exige_valeur "$1" "${2:-}"; COULEUR="$2";           shift 2 ;;
        --couleur=*)      COULEUR="${1#--couleur=}";                          shift ;;
        --sans-couleur)   COULEUR="non";                                      shift ;;

        -h|--help|--aide) aide; exit 0 ;;
        --)               shift; break ;;
        *)                printf 'Argument inconnu : %s   (-h pour aide)\n' "$1" >&2; exit 1 ;;
    esac
done

case "$COULEUR" in oui|non|auto) ;; *) printf 'ERREUR : --couleur attend oui, non ou auto.\n' >&2; exit 1 ;; esac
init_affichage

# Le fichier de configuration est un bout de shell : on le lit dans un
# sous-shell d'abord, pour qu'une faute de frappe n'exécute rien
# d'irréversible avant d'être signalée.
if [[ -n "$CONF" ]]; then
    [[ -r "$CONF" ]] || { erreur "configuration illisible : $CONF"; exit 1; }
    if ! bash -n "$CONF" 2>/dev/null; then
        erreur "erreur de syntaxe dans $CONF"
        bash -n "$CONF"
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$CONF" || { erreur "échec du chargement de $CONF"; exit 1; }
fi

# Les options de la ligne de commande passent en dernier.
# Le test sur la taille évite l'erreur de set -u sur un tableau vide
# avec les bash antérieurs à 4.4.
if (( ${#OPT[@]} > 0 )); then
    for cle in "${!OPT[@]}"; do
        printf -v "$cle" '%s' "${OPT[$cle]}"
    done
fi

calculer_chemins
definir_commandes


# --- Saisies ---------------------------------------------------------
# Les saisies doivent venir du clavier, pas de l'entrée standard, qui peut
# être occupée par une commande. On teste si le terminal est ouvrable.
if (exec 3< /dev/tty) 2>/dev/null; then
    ENTREE="/dev/tty"
    INTERACTIF="oui"
else
    ENTREE="/dev/stdin"
    INTERACTIF="non"
fi

# Sortie propre commune aux saisies interrompues (Ctrl-C, Ctrl-D).
# Inventer une valeur ici serait dangereux : on préfère s'arrêter.
abandon() {
    printf '\n'
    erreur "saisie interrompue — arrêt."
    exit 130
}

# lire <invite> <nom_variable>
# Renvoie 1 si la saisie a échoué : à l'appelant de décider.
lire() {
    local invite="$1" cible="$2"
    if [[ "$SANS_QUESTION" == "true" ]]; then
        printf -v "$cible" '%s' ""       # comme si on avait tapé Entrée
        printf '%s%s[-y]%s\n' "$invite" "$ESTOMPE" "$C0"
        return 0
    fi
    read -r -p "$invite" "$cible" < "$ENTREE"
}

# lire_edit <valeur_initiale> <nom_variable> : ligne pré-remplie, modifiable
lire_edit() {
    read -r -e -i "$1" -p "  ${CYAN}\$${C0} " "$2" < "$ENTREE" || true
}

# demander_oui_non <invite> : vrai si l'utilisateur accepte (défaut oui)
demander_oui_non() {
    local r=""
    lire "$1" r || abandon
    case "${r,,}" in n|non|q) return 1 ;; *) return 0 ;; esac
}


# --- Récapitulatif ---------------------------------------------------
# Une ligne par étape traitée : "code|détail|titre". Rempli au fil de
# l'eau, affiché à la sortie du script — y compris sur un arrêt anticipé
# (q, Ctrl-C), d'où le trap EXIT.
RECAP=()
NB_OK=0; NB_KO=0; NB_PASSEES=0

symbole() {
    case "$1" in
        ok)    printf '%s✅%s' "$VERT"   "$C0" ;;
        ko)    printf '%s❌%s' "$ROUGE"  "$C0" ;;
        skip)  printf '%s⏭️ %s' "$ESTOMPE" "$C0" ;;
        int)   printf '%s⚠️ %s' "$JAUNE"  "$C0" ;;
        sim)   printf '%s👁️ %s' "$BLEU"   "$C0" ;;
        *)     printf '  ' ;;
    esac
}

recap() {
    (( ${#RECAP[@]} == 0 )) && return
    local l c d t

    printf '\n'
    regle "$GRAS"
    printf ' %sRécapitulatif%s   %s%s · %s · %s%s\n' \
           "$GRAS" "$C0" "$ESTOMPE" "$PC" "$SALLE" "$OS" "$C0"
    regle "$GRAS"

    for l in "${RECAP[@]}"; do
        c="${l%%|*}"; d="${l#*|}"; t="${d#*|}"; d="${d%%|*}"
        # Le détail est en ASCII, donc son alignement ne dépend pas de la
        # locale ; le titre, accentué, est rejeté en fin de ligne.
        printf '  %s %s%-10s%s %s\n' "$(symbole "$c")" "$ESTOMPE" "$d" "$C0" "$t"
    done

    regle
    printf '  %s%d réussie%s%s · %s%d en échec%s · %s%d passée%s%s · total %s\n' \
           "$VERT"    "$NB_OK"      "$(pluriel "$NB_OK")"      "$C0" \
           "$ROUGE"   "$NB_KO"      "$C0" \
           "$ESTOMPE" "$NB_PASSEES" "$(pluriel "$NB_PASSEES")" "$C0" \
           "$(duree $SECONDS)"
    printf '  %sjournal  %s%s\n' "$ESTOMPE" "$LOG" "$C0"

    ecrire_rapport
}

# Le rapport est la trace qu'on garde : il doit survivre à la fermeture
# du terminal, et rester lisible sans couleur.
ecrire_rapport() {
    [[ -n "${DIR_LOGS:-}" && -d "${DIR_LOGS:-}" ]] || return 0
    local f="$DIR_LOGS/${PREFIX}_rapport.txt" l c d t

    {
        printf 'Rapport forensic.sh\n'
        printf '  poste      %s / %s / %s\n' "$PC" "$SALLE" "$OS"
        printf '  image      %s\n' "$IMAGE"
        printf '  opérateur  %s\n' "$OPERATEUR"
        printf '  machine    %s\n' "$(hostname 2>/dev/null || printf inconnue)"
        printf '  début      %s\n' "$DEBUT_HORODATE"
        printf '  fin        %s\n' "$(date '+%F %T %z')"
        printf '  durée      %s\n' "$(duree $SECONDS)"
        printf '\n'
        for l in "${RECAP[@]}"; do
            c="${l%%|*}"; d="${l#*|}"; t="${d#*|}"; d="${d%%|*}"
            printf '  %-5s %-10s %s\n' "$c" "$d" "$t"
        done
        printf '\n  %d réussies, %d en échec, %d passées\n' "$NB_OK" "$NB_KO" "$NB_PASSEES"
    } > "$f" 2>/dev/null && printf '  %srapport  %s%s\n' "$ESTOMPE" "$f" "$C0"
}

LOG="/dev/null"
DEBUT_HORODATE="$(date '+%F %T %z')"
trap recap EXIT

# Ctrl-C ne doit pas tuer le script. Bash met le gestionnaire en attente
# tant qu'une commande tourne au premier plan : le signal atteint d'abord
# la commande, puis on reprend la main ici.
INTERROMPU=0
trap 'INTERROMPU=1' INT

# journal <texte...> : une ligne horodatée dans le journal
journal() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$LOG"
}


# --- Valeurs, listes et emboîtement ----------------------------------
#
# Deux syntaxes, deux mécanismes :
#   [[nom]]  une valeur, mémorisée dans REPONSES et réutilisée partout
#   {{nom}}  une liste, qui multiplie l'étape en autant d'itérations
#
# Les motifs sont dans des variables : écrits directement dans un test
# [[ ... =~ ... ]], leurs accolades et crochets demanderaient une couche
# d'échappement de plus, illisible.
RE_SIMPLE='\[\[([a-zA-Z0-9_]+)\]\]'
RE_LISTE='\{\{([a-zA-Z0-9_]+)\}\}'

# Ces tableaux sont initialisés avec =() et pas seulement déclarés :
# sous set -u, un « declare -A X » sans valeur rend ${#X[@]} illégal
# tant que rien n'y a été écrit — panne qui ne se voit qu'au premier
# lancement où la toute première étape utilise une liste.
declare -A REPONSES=()        # [[nom]]  -> valeur saisie
declare -A GENERATEUR=()      # nom de liste -> commande qui la produit
declare -A CACHE_LISTE=()     # commande déjà exécutée -> ses lignes
declare -A LISTE_FIGEE=()     # nom -> valeurs imposées par --liste
declare -A BINDINGS=()        # liaisons de la boucle en cours (échappées)
declare -A AFFICHE=()         # les mêmes, brutes, pour l'affichage

# echapper_apostrophes <valeur>
# Les valeurs de liste viennent d'un programme, pas de vous : un nom de
# fichier peut contenir une apostrophe et casser la commande. On la
# neutralise. C'est aussi pourquoi la documentation insiste pour que
# {{nom}} soit toujours écrit entre apostrophes.
echapper_apostrophes() {
    local v="$1"
    printf "%s" "${v//\'/\'\\\'\'}"
}

# charger_listes : LISTES (tableau lisible) -> GENERATEUR (table de correspondance)
charger_listes() {
    local e nom gen
    (( ${#LISTES[@]} == 0 )) && return 0
    for e in "${LISTES[@]}"; do
        [[ "$e" == *"|"* ]] || { erreur "LISTES : il faut nom|commande — reçu : $e"; exit 1; }
        nom="${e%%|*}"; gen="${e#*|}"
        [[ "$nom" =~ ^[a-zA-Z0-9_]+$ ]] || { erreur "LISTES : nom invalide « $nom »"; exit 1; }
        [[ "$nom" == *_libelle ]] && { erreur "LISTES : le suffixe _libelle est réservé ($nom)"; exit 1; }
        [[ -n "$gen" ]] || { erreur "LISTES : commande vide pour « $nom »"; exit 1; }
        [[ -n "${GENERATEUR[$nom]:-}" ]] && { erreur "LISTES : « $nom » est défini deux fois"; exit 1; }
        GENERATEUR["$nom"]="$gen"
    done
    return 0
}

# substituer_liaisons <texte> : remplace les {{nom}} déjà liés
substituer_liaisons() {
    local t="$1" k
    if (( ${#BINDINGS[@]} > 0 )); then
        for k in "${!BINDINGS[@]}"; do
            t="${t//\{\{$k\}\}/${BINDINGS[$k]}}"
        done
    fi
    printf '%s' "$t"
}

# liste_de <nom> : le nom de liste réellement concerné.
# {{home_libelle}} désigne la liste "home" ; on renvoie le nom de base.
liste_de() {
    local nom="$1"
    if [[ -z "${GENERATEUR[$nom]:-}" && -z "${LISTE_FIGEE[$nom]:-}" && "$nom" == *_libelle ]]; then
        nom="${nom%_libelle}"
    fi
    printf '%s' "$nom"
}

# generer_liste <nom> -> remplit VALEURS et LIBELLES, renvoie 0 ou 1
# Copiez VALEURS immédiatement après l'appel : un appel imbriqué
# (une liste qui en appelle une autre) l'écrase.
VALEURS=(); LIBELLES=()
generer_liste() {
    local nom="$1" gen brut sortie rc ligne val lib
    VALEURS=(); LIBELLES=()

    # 1. Valeurs imposées par --liste : rien à exécuter.
    if [[ -n "${LISTE_FIGEE[$nom]:-}" ]]; then
        while IFS= read -r ligne; do
            [[ -n "$ligne" ]] && { VALEURS+=("$ligne"); LIBELLES+=(""); }
        done <<< "${LISTE_FIGEE[$nom]}"
        return 0
    fi

    brut="${GENERATEUR[$nom]:-}"
    [[ -n "$brut" ]] || { erreur "aucune liste « $nom » dans LISTES (voir --vars)"; return 1; }

    # 2. La commande de liste peut contenir des [[valeurs]] et des
    #    {{listes}} déjà liées : on les remplace avant de l'exécuter.
    resoudre_simples "$brut" || return 1
    gen="$(substituer_liaisons "$CMD")"

    # 3. Cache : mmls ne tourne qu'une fois, même s'il sert au menu de
    #    [[offset]] et à une étape répétée. La clé est la commande
    #    résolue, donc une liste imbriquée est bien régénérée par home.
    if [[ -n "${CACHE_LISTE[$gen]:-}" ]]; then
        sortie="${CACHE_LISTE[$gen]}"
        [[ "$sortie" == $'\001vide' ]] && sortie=""
    else
        journal "LISTE $nom : $gen"
        sortie="$(eval "$gen" 2>> "$LOG")"
        rc=$?
        if (( rc != 0 && ${#sortie} == 0 )); then
            erreur "la liste « $nom » a échoué (code $rc) — voir $LOG"
            return 1
        fi
        CACHE_LISTE["$gen"]="${sortie:-$'\001vide'}"
    fi

    # 4. Une ligne = une valeur, éventuellement "valeur<TAB>libellé".
    while IFS= read -r ligne; do
        [[ -z "$ligne" ]] && continue
        if [[ "$ligne" == *$'\t'* ]]; then
            val="${ligne%%$'\t'*}"; lib="${ligne#*$'\t'}"
        else
            val="$ligne"; lib=""
        fi
        VALEURS+=("$val"); LIBELLES+=("$lib")
    done <<< "$sortie"

    (( ${#VALEURS[@]} > 0 )) || { attention "la liste « $nom » est vide"; return 1; }
    return 0
}


# valeur_valide <valeur> : refuse le vide et les marqueurs imbriqués,
# qui relanceraient la détection sans fin.
valeur_valide() {
    if [[ -z "$1" ]]; then
        printf '    %svaleur vide refusée%s\n' "$JAUNE" "$C0"; return 1
    elif [[ "$1" == *'[['* || "$1" == *'{{'* ]]; then
        printf '    %svaleur interdite : elle contient [[ ou {{%s\n' "$JAUNE" "$C0"; return 1
    fi
    return 0
}

# demander_valeur <nom> -> VALEUR
# Menu numéroté si une liste du même nom existe, saisie libre sinon.
# Un menu vaut mieux qu'une question ouverte : l'offset d'une partition
# ne se devine pas, et le recopier à la main est la première source
# d'erreur de toute la chaîne.
VALEUR=""
demander_valeur() {
    local nom="$1" i n choix aff
    local -a v=() l=()

    if [[ -n "${GENERATEUR[$nom]:-}" || -n "${LISTE_FIGEE[$nom]:-}" ]]; then
        if generer_liste "$nom"; then
            v=("${VALEURS[@]}"); l=("${LIBELLES[@]}")
        fi
    fi

    n=${#v[@]}
    if (( n > 0 )); then
        printf '    %s┌%s %s[[%s]]%s — %d proposition%s\n' \
               "$ESTOMPE" "$C0" "$CYAN" "$nom" "$C0" "$n" "$(pluriel "$n")"
        for i in "${!v[@]}"; do
            aff="${l[$i]}"
            printf '    %s│%s %s%2d%s  %s%-14s%s %s%s%s\n' \
                   "$ESTOMPE" "$C0" "$GRAS" $(( i + 1 )) "$C0" \
                   "$VERT" "${v[$i]}" "$C0" "$ESTOMPE" "$aff" "$C0"
        done
        printf '    %s│%s %s a%s  saisir une autre valeur\n' "$ESTOMPE" "$C0" "$GRAS" "$C0"

        while true; do
            choix=""
            lire "    $ESTOMPE└$C0 choix [1] : " choix || abandon
            [[ -z "$choix" ]] && choix=1
            if [[ "${choix,,}" == "a" ]]; then
                break                              # bascule en saisie libre
            elif [[ "$choix" =~ ^[0-9]+$ ]] && (( choix >= 1 && choix <= n )); then
                VALEUR="${v[$(( choix - 1 ))]}"
                printf '    %s→ %s%s\n' "$VERT" "$VALEUR" "$C0"
                return 0
            else
                printf '    %schoix hors liste%s\n' "$JAUNE" "$C0"
            fi
        done
    fi

    # Saisie libre. En mode -y, il n'y a personne pour répondre : mieux
    # vaut s'arrêter net que lancer une commande amputée.
    if [[ "$SANS_QUESTION" == "true" ]]; then
        erreur "[[$nom]] n'a pas de valeur et -y interdit de la demander."
        erreur "Fournissez-la : --var $nom=..."
        exit 1
    fi

    VALEUR=""
    while true; do
        lire "    ${CYAN}[[$nom]]${C0} : " VALEUR || abandon
        valeur_valide "$VALEUR" && break
    done
    return 0
}

# resoudre_simples <commande> : remplace les [[valeurs]], résultat dans $CMD.
# Le résultat passe par une variable et non par $(...), car un sous-shell
# perdrait les valeurs mémorisées dans REPONSES.
# Recopiez $CMD tout de suite : un appel imbriqué l'écrase.
CMD=""
resoudre_simples() {
    local cmd="$1" nom val
    while [[ "$cmd" =~ $RE_SIMPLE ]]; do
        nom="${BASH_REMATCH[1]}"
        if [[ -n "${REPONSES[$nom]:-}" ]]; then
            val="${REPONSES[$nom]}"          # déjà connu, on réutilise
        else
            demander_valeur "$nom"
            val="$VALEUR"
            REPONSES["$nom"]="$val"          # mémorisé pour la suite
        fi
        cmd="${cmd//\[\[$nom\]\]/$val}"
    done
    CMD="$cmd"
    return 0
}


# liste_a_parcourir <nom> : par quelle liste faut-il commencer ?
# Si la liste "fichier" a besoin de {{home}}, écrire {{fichier}} seul
# doit quand même faire boucler sur les homes : on remonte la chaîne
# des dépendances jusqu'à celle qui ne dépend de rien.
liste_a_parcourir() {
    local nom vu=" " gen dep
    nom="$(liste_de "$1")"
    while true; do
        [[ "$vu" == *" $nom "* ]] && { erreur "dépendance circulaire entre listes : $nom"; return 1; }
        vu+="$nom "
        gen="${GENERATEUR[$nom]:-}"
        [[ -n "$gen" ]] || break                 # liste figée : pas de dépendance
        gen="$(substituer_liaisons "$gen")"
        if [[ "$gen" =~ $RE_LISTE ]]; then
            dep="$(liste_de "${BASH_REMATCH[1]}")"
            nom="$dep"
        else
            break
        fi
    done
    printf '%s' "$nom"
    return 0
}

# expanser <commande> : développe les {{listes}} en une itération par
# combinaison. Remplit EXP_CMDS (commandes prêtes) et EXP_LABELS
# (« home=Users/alice · fichier=… », pour l'affichage).
# Une étape sans {{liste}} donne exactement une entrée : le reste du
# script n'a donc qu'un seul cas à traiter.
EXP_CMDS=(); EXP_LABELS=(); EXP_TRONQUE=0
expanser() {
    EXP_CMDS=(); EXP_LABELS=(); EXP_TRONQUE=0
    BINDINGS=(); AFFICHE=()
    _expanser "$1" "" 0
}

_expanser() {
    local cmd="$1" label="$2" prof="$3"
    local nom cible i val lib etiq rc
    local -a v=() l=()

    (( prof > 6 )) && { erreur "plus de 6 listes emboîtées : refusé"; return 1; }
    (( INTERROMPU )) && return 130
    (( EXP_TRONQUE )) && return 0

    cmd="$(substituer_liaisons "$cmd")"

    if [[ ! "$cmd" =~ $RE_LISTE ]]; then
        if (( ${#EXP_CMDS[@]} >= MAX_ITERATIONS )); then EXP_TRONQUE=1; return 0; fi
        EXP_CMDS+=("$cmd"); EXP_LABELS+=("$label")
        return 0
    fi

    nom="${BASH_REMATCH[1]}"
    cible="$(liste_a_parcourir "$nom")" || return 1
    if [[ -z "${GENERATEUR[$cible]:-}" && -z "${LISTE_FIGEE[$cible]:-}" ]]; then
        erreur "aucune liste « $cible » dans LISTES (voir --vars)"
        return 1
    fi

    generer_liste "$cible" || return 1
    v=("${VALEURS[@]}"); l=("${LIBELLES[@]}")

    for i in "${!v[@]}"; do
        (( INTERROMPU )) && return 130
        (( EXP_TRONQUE )) && return 0
        val="${v[$i]}"; lib="${l[$i]}"

        # Deux copies : l'échappée part dans la commande, la brute sert
        # aux étiquettes, où un '\'' serait illisible.
        BINDINGS["$cible"]="$(echapper_apostrophes "$val")"
        AFFICHE["$cible"]="$val"
        BINDINGS["${cible}_libelle"]="$(echapper_apostrophes "${lib:-$val}")"
        AFFICHE["${cible}_libelle"]="${lib:-$val}"

        etiq="$cible=${lib:-$val}"
        _expanser "$cmd" "${label:+$label · }$etiq" $(( prof + 1 ))
        rc=$?

        unset "BINDINGS[$cible]" "AFFICHE[$cible]"
        unset "BINDINGS[${cible}_libelle]" "AFFICHE[${cible}_libelle]"

        (( rc != 0 )) && return "$rc"
    done
    return 0
}

# scanner_placeholders : inventaire des [[valeurs]] et {{listes}}, avec
# les étapes où elles servent. Utilisé par --vars et pour refuser un
# --var mal orthographié.
scanner_placeholders() {
    PH_SIMPLES=(); USAGE_SIMPLES=(); PH_LISTES=(); USAGE_LISTES=()
    local i=0 e cmd nom

    _noter() {   # _noter <tableau_noms> <tableau_usages> <nom> <étape>
        local -n noms="$1"; local -n usages="$2"
        local nom="$3" etape="$4" j trouve=-1
        for j in "${!noms[@]}"; do [[ "${noms[$j]}" == "$nom" ]] && trouve=$j; done
        if (( trouve < 0 )); then noms+=("$nom"); usages+=("$etape")
        elif [[ "${usages[$trouve]}" != *"$etape"* ]]; then usages[$trouve]+=", $etape"; fi
    }

    for e in "${COMMANDES[@]}"; do
        i=$(( i + 1 ))
        cmd="${e#*|}"; cmd="${cmd#*|}"
        while [[ "$cmd" =~ $RE_SIMPLE ]]; do
            nom="${BASH_REMATCH[1]}"
            _noter PH_SIMPLES USAGE_SIMPLES "$nom" "$i"
            cmd="${cmd//\[\[$nom\]\]/}"
        done
        while [[ "$cmd" =~ $RE_LISTE ]]; do
            nom="${BASH_REMATCH[1]}"
            cmd="${cmd//\{\{$nom\}\}/}"
            _noter PH_LISTES USAGE_LISTES "$(liste_de "$nom")" "$i"
        done
    done

    # Une liste peut en appeler une autre : {{fichier}} déclenchera la
    # boucle sur {{home}}, qui réclamera [[offset]]. On suit la chaîne,
    # sans quoi --vars mentirait sur ce qui va réellement être demandé.
    # Le tableau grandit pendant le parcours : d'où l'index explicite.
    local k=0 gen
    while (( k < ${#PH_LISTES[@]} )); do
        gen="${GENERATEUR[${PH_LISTES[$k]}]:-}"
        nom="${PH_LISTES[$k]}"
        k=$(( k + 1 ))
        while [[ "$gen" =~ $RE_SIMPLE ]]; do
            local s1="${BASH_REMATCH[1]}"
            gen="${gen//\[\[$s1\]\]/}"
            _noter PH_SIMPLES USAGE_SIMPLES "$s1" "liste $nom"
        done
        while [[ "$gen" =~ $RE_LISTE ]]; do
            local s2="${BASH_REMATCH[1]}"
            gen="${gen//\{\{$s2\}\}/}"
            _noter PH_LISTES USAGE_LISTES "$(liste_de "$s2")" "liste $nom"
        done
    done

    unset -f _noter
}


# --- Vérifications de départ -----------------------------------------
# Mieux vaut échouer ici que découvrir le problème à la cinquième étape.

# analyser_validation <champ> : "true", "false,log", "true,continu"...
# Remplit F_VALIDER, F_LOG, F_STOP, F_CONTINU. Renvoie 1 si invalide.
analyser_validation() {
    local champ="${1,,}" opt
    F_VALIDER=""; F_LOG=0; F_STOP=0; F_CONTINU=0
    local IFS=,
    for opt in $champ; do
        case "$opt" in
            true|vrai|oui|1)   F_VALIDER="true"  ;;
            false|faux|non|0)  F_VALIDER="false" ;;
            log|journal)       F_LOG=1 ;;
            stop|arret)        F_STOP=1 ;;
            continu|continue)  F_CONTINU=1 ;;
            "")                ;;
            *) MSG_VALIDATION="option inconnue « $opt »"; return 1 ;;
        esac
    done
    [[ -n "$F_VALIDER" ]] || { MSG_VALIDATION="il manque true ou false"; return 1; }
    (( F_STOP && F_CONTINU )) && { MSG_VALIDATION="stop et continu s'excluent"; return 1; }
    return 0
}

(( ${#COMMANDES[@]} > 0 )) || { erreur "le tableau COMMANDES est vide."; exit 1; }

MSG_VALIDATION=""
for entree in "${COMMANDES[@]}"; do
    reste="${entree#*|}"
    if [[ "$entree" != *"|"* || "$reste" != *"|"* ]]; then
        erreur "format (il faut Titre|validation|commande) :"
        printf '  %s\n' "$entree" >&2
        exit 1
    fi
    # Sans ce contrôle, "Titre|true|" lancerait un eval vide, compté réussi.
    if [[ -z "${reste#*|}" ]]; then
        erreur "commande vide :"; printf '  %s\n' "$entree" >&2; exit 1
    fi
    # Sans celui-ci, "echo bonjour" seul serait exécuté sans rien demander.
    if ! analyser_validation "${reste%%|*}"; then
        erreur "validation « ${reste%%|*} » invalide : $MSG_VALIDATION"
        printf '  %s\n' "$entree" >&2
        exit 1
    fi
done

charger_listes
scanner_placeholders

# --vars : on affiche et on s'arrête, sans rien exécuter ni rien créer.
if [[ "$LISTER_VARS" == "true" ]]; then
    printf '\n'
    if (( ${#PH_SIMPLES[@]} == 0 && ${#PH_LISTES[@]} == 0 )); then
        info "aucune valeur à fournir : les commandes sont complètes."
    fi
    if (( ${#PH_SIMPLES[@]} > 0 )); then
        printf ' %s[[valeurs]] — une valeur, demandée une seule fois%s\n' "$GRAS" "$C0"
        for i in "${!PH_SIMPLES[@]}"; do
            src="saisie"
            [[ -n "${GENERATEUR[${PH_SIMPLES[$i]}]:-}" ]] && src="menu"
            printf '   %s%-18s%s %s%-6s%s %sétape(s) %s%s\n' \
                   "$CYAN" "${PH_SIMPLES[$i]}" "$C0" "$VERT" "$src" "$C0" \
                   "$ESTOMPE" "${USAGE_SIMPLES[$i]}" "$C0"
        done
        printf '   %s--var nom=valeur   (répétable)%s\n' "$ESTOMPE" "$C0"
    fi
    if (( ${#PH_LISTES[@]} > 0 )); then
        printf '\n %s{{listes}} — plusieurs valeurs, l'"'"'étape est répétée%s\n' "$GRAS" "$C0"
        for i in "${!PH_LISTES[@]}"; do
            printf '   %s%-18s%s %sétape(s) %s%s\n' \
                   "$MAGENTA" "${PH_LISTES[$i]}" "$C0" "$ESTOMPE" "${USAGE_LISTES[$i]}" "$C0"
            printf '   %s%-18s   %s%s\n' "" "" "${GENERATEUR[${PH_LISTES[$i]}]:-(figée)}" ""
        done
        printf '   %s--liste nom=v1,v2  fige une liste sans l'"'"'interroger%s\n' "$ESTOMPE" "$C0"
    fi
    printf '\n'
    exit 0
fi

# Application des --var et --liste. Un nom inconnu est refusé : c'est
# presque toujours une faute de frappe, et la valeur serait silencieusement
# ignorée, ce qui est bien pire qu'une erreur.
connu_dans() {   # connu_dans <nom> <tableau...>
    local nom="$1"; shift
    local x
    for x in "$@"; do [[ "$x" == "$nom" ]] && return 0; done
    return 1
}

if (( ${#PRESETS[@]} > 0 )); then
    for p in "${PRESETS[@]}"; do
        [[ "$p" == *=* ]] || { erreur "--var attend nom=valeur, reçu : $p"; exit 1; }
        nom="${p%%=*}"; val="${p#*=}"
        [[ "$nom" =~ ^[a-zA-Z0-9_]+$ ]] || { erreur "nom de variable invalide : $nom"; exit 1; }
        valeur_valide "$val" || { erreur "valeur refusée pour $nom"; exit 1; }
        connu_dans "$nom" ${PH_SIMPLES[@]+"${PH_SIMPLES[@]}"} \
            || { erreur "aucun [[$nom]] dans les commandes (voir --vars)"; exit 1; }
        REPONSES["$nom"]="$val"
    done
fi

if (( ${#PRESETS_LISTE[@]} > 0 )); then
    for p in "${PRESETS_LISTE[@]}"; do
        [[ "$p" == *=* ]] || { erreur "--liste attend nom=v1,v2, reçu : $p"; exit 1; }
        nom="${p%%=*}"; val="${p#*=}"
        [[ "$nom" =~ ^[a-zA-Z0-9_]+$ ]] || { erreur "nom de liste invalide : $nom"; exit 1; }
        [[ -n "$val" ]] || { erreur "--liste $nom : aucune valeur"; exit 1; }
        connu_dans "$nom" ${PH_LISTES[@]+"${PH_LISTES[@]}"} \
            || { erreur "aucune liste « $nom » utilisée (voir --vars)"; exit 1; }
        LISTE_FIGEE["$nom"]="${val//,/$'\n'}"
    done
fi

# --etapes : le plan, sans rien exécuter.
if [[ "$LISTER_ETAPES" == "true" ]]; then
    printf '\n'
    regle "$GRAS"
    printf ' %sPlan — %d étapes%s\n' "$GRAS" "${#COMMANDES[@]}" "$C0"
    regle "$GRAS"
    i=0
    for entree in "${COMMANDES[@]}"; do
        i=$(( i + 1 ))
        reste="${entree#*|}"
        analyser_validation "${reste%%|*}"
        # Les marques sont en ASCII : leur colonne reste alignée quelle
        # que soit la locale, ce qui ne serait pas vrai d'un titre accentué.
        marques=""
        [[ "$F_VALIDER" == "true" ]] && marques+="valider "
        (( F_LOG ))     && marques+="log "
        (( F_STOP ))    && marques+="stop "
        (( F_CONTINU )) && marques+="continu "
        [[ "${reste#*|}" == *"{{"* ]] && marques+="repetee "
        printf '  %s%2d%s  %s%-18s%s %s\n' "$GRAS" "$i" "$C0" "$ESTOMPE" "$marques" "$C0" "${entree%%|*}"
        printf '      %s%s%s\n' "$ESTOMPE" "${reste#*|}" "$C0"
    done
    printf '\n'
    exit 0
fi

# Contrôles qui n'ont de sens que si l'on va vraiment exécuter.
[[ -e "$IMAGE" ]] || { erreur "image absente : $IMAGE"; exit 1; }
[[ -r "$IMAGE" ]] || { erreur "image illisible (droits ?) : $IMAGE"; exit 1; }

# Un fuseau mal orthographié ne se voit qu'à la relecture de la timeline,
# des heures plus tard : autant le dire tout de suite.
if [[ -d /usr/share/zoneinfo && ! -e "/usr/share/zoneinfo/$TZ_MACTIME" ]]; then
    attention "fuseau inconnu du système : $TZ_MACTIME (mactime risque de refuser)"
fi

MANQUANTS=""
for b in "${REQUIS[@]}"; do
    command -v "$b" > /dev/null 2>&1 || MANQUANTS="$MANQUANTS $b"
done
[[ -n "$MANQUANTS" ]] && attention "binaires absents :$MANQUANTS"

# --- Préparation des dossiers ----------------------------------------
# ${!DIR_@} liste les noms de variables commençant par DIR_,
# ${!nom} donne ensuite la valeur de chacune.
printf '\n %sDossiers%s\n' "$GRAS" "$C0"
for nom in ${!DIR_@}; do
    d="${!nom}"
    [[ -n "$d" ]] || { erreur "$nom est vide."; exit 1; }
    if [[ -d "$d" ]]; then
        printf '  %sok    %s%s\n' "$ESTOMPE" "$d" "$C0"
    elif [[ "$SIMULATION" == "true" ]]; then
        printf '  %s(sim) à créer : %s%s\n' "$BLEU" "$d" "$C0"
    else
        mkdir -p "$d" || { erreur "création impossible : $d"; exit 1; }
        printf '  %scréé  %s%s\n' "$VERT" "$d" "$C0"
    fi
    [[ "$SIMULATION" == "true" ]] || [[ -w "$d" ]] || attention "dossier non inscriptible : $d"
done

# Le journal ne peut être ouvert qu'une fois son dossier créé.
if [[ "$SIMULATION" == "true" ]]; then
    LOG="/dev/null"
else
    LOG="$DIR_LOGS/${PREFIX}_script.log"
    : >> "$LOG" || { erreur "journal non inscriptible : $LOG"; exit 1; }
fi


# --- Reprise après interruption --------------------------------------
# Une image de 500 Go et un carving de six heures : un script coupé ne
# doit pas obliger à tout recommencer. On note l'empreinte des étapes
# réussies ; --reprendre les saute. L'empreinte porte sur le titre ET la
# commande : modifiez la commande, l'étape sera rejouée.
ETAT="${DIR_LOGS:-/tmp}/${PREFIX}_etat.txt"

empreinte() {
    local s="$1"
    if command -v sha1sum > /dev/null 2>&1;  then printf '%s' "$s" | sha1sum  | cut -d' ' -f1
    elif command -v shasum > /dev/null 2>&1; then printf '%s' "$s" | shasum   | cut -d' ' -f1
    else                                          printf '%s' "$s" | cksum    | tr -d ' '
    fi
}

deja_faite() {
    [[ "$REPRENDRE" == "true" && -r "$ETAT" ]] || return 1
    grep -qxF "$1" "$ETAT" 2>/dev/null
}

marquer_faite() {
    [[ "$SIMULATION" == "true" ]] && return 0
    printf '%s\n' "$1" >> "$ETAT" 2>/dev/null || true
}


# --- Filtre d'étapes --------------------------------------------------
# --seulement 2,5-7 et --depuis 4 : refaire une étape ratée sans
# rejouer les cinq heures qui précèdent.
[[ "$DEPUIS" =~ ^[0-9]+$ ]] || { erreur "--depuis attend un numéro d'étape"; exit 1; }

# Contrôle immédiat de --seulement : signaler « 2-x » après cinq minutes
# d'exécution serait la pire façon de l'apprendre.
if [[ -n "$FILTRE_ETAPES" ]]; then
    ANCIEN_IFS="$IFS"; IFS=,
    for morceau in $FILTRE_ETAPES; do
        [[ "$morceau" =~ ^[0-9]+(-[0-9]+)?$ ]] || {
            IFS="$ANCIEN_IFS"
            erreur "--seulement : « $morceau » n'est ni un numéro ni un intervalle"
            exit 1
        }
    done
    IFS="$ANCIEN_IFS"
    (( DEPUIS > 0 )) && attention "--seulement et --depuis se cumulent : une étape doit satisfaire les deux"
fi

etape_retenue() {
    local n="$1" morceau debut fin
    (( DEPUIS > 0 && n < DEPUIS )) && return 1
    [[ -z "$FILTRE_ETAPES" ]] && return 0
    local IFS=,
    for morceau in $FILTRE_ETAPES; do
        if [[ "$morceau" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            debut="${BASH_REMATCH[1]}"; fin="${BASH_REMATCH[2]}"
            (( n >= debut && n <= fin )) && return 0
        elif [[ "$morceau" =~ ^[0-9]+$ ]]; then
            (( n == morceau )) && return 0
        else
            erreur "--seulement : « $morceau » n'est ni un numéro ni un intervalle"
            exit 1
        fi
    done
    return 1
}


# --- Bandeau de démarrage --------------------------------------------
printf '\n'
regle "$GRAS"
printf ' %sforensic.sh%s  %s%s · %s · %s%s\n' "$GRAS" "$C0" "$CYAN" "$PC" "$SALLE" "$OS" "$C0"
regle "$GRAS"
entete "image"     "$IMAGE"
entete "sortie"    "$DEST"
entete "fuseau"    "$TZ_MACTIME"
entete "analyste"  "$OPERATEUR"
entete "journal"   "$LOG"
[[ -n "$CONF" ]]                    && entete "config"  "$CONF"
[[ "$SIMULATION"    == "true" ]]    && printf '  %s%-10s%s %s\n' "$BLEU"  "simulation" "$C0" "aucune commande d'étape ne sera exécutée"
[[ "$SANS_QUESTION" == "true" ]]    && printf '  %s%-10s%s %s\n' "$JAUNE" "-y" "$C0" "aucune question ne sera posée"
[[ "$TOUT_VALIDER"  == "true" ]]    && printf '  %s%-10s%s %s\n' "$ESTOMPE" "-v" "$C0" "chaque étape sera confirmée"
[[ "$REPRENDRE"     == "true" ]]    && printf '  %s%-10s%s %s\n' "$ESTOMPE" "reprise" "$C0" "les étapes déjà réussies seront sautées"
[[ -n "$FILTRE_ETAPES" ]]           && printf '  %s%-10s%s %s\n' "$ESTOMPE" "filtre" "$C0" "étapes $FILTRE_ETAPES"
(( DEPUIS > 0 ))                    && printf '  %s%-10s%s %s\n' "$ESTOMPE" "depuis" "$C0" "$DEPUIS"

journal "=== démarrage — $PC/$SALLE/$OS — image $IMAGE — opérateur $OPERATEUR"


# --- Exécution d'une commande ----------------------------------------
# DUREE_S est posé au retour ; le code de sortie est celui de la fonction.
DUREE_S=0
executer_une() {
    local cmd="$1" avec_log="$2"
    local debut=$SECONDS rc

    INTERROMPU=0
    journal "$cmd"

    if [[ "$SIMULATION" == "true" ]]; then
        DUREE_S=0
        return 0
    fi

    if (( avec_log )); then
        # Un tube, et non une substitution de processus : le shell attend
        # alors la fin de tee, et PIPESTATUS donne le vrai code de la
        # commande. En contrepartie elle perd son terminal — c'est
        # pourquoi l'option log est explicite, jamais automatique.
        eval "$cmd" 2>&1 | tee -a "$LOG"
        rc=${PIPESTATUS[0]}
    else
        eval "$cmd"
        rc=$?
    fi

    DUREE_S=$(( SECONDS - debut ))
    journal "code $rc en $(duree $DUREE_S)"
    return "$rc"
}


# --- Affichage d'une étape -------------------------------------------
titre_etape() {
    local num="$1" total="$2" titre="$3"
    printf '\n'
    regle
    printf ' %s  %s[%d/%d]%s %s%s%s\n' \
           "$(barre "$(( num - 1 ))" "$total")" \
           "$ESTOMPE" "$num" "$total" "$C0" "$GRAS" "$titre" "$C0"
    regle
}

afficher_commande() {
    printf '  %s$%s %s\n' "$CYAN" "$C0" "$1"
}

# Sur un terminal étroit, une commande de 300 caractères devient une
# bouillie ; « s » la redonne coupée aux espaces.
afficher_commande_lisible() {
    printf '%s\n' "$1" | fold -s -w $(( LARGEUR - 6 )) | sed "s/^/      /"
}

# resume_iterations : combien d'itérations, et lesquelles
resume_iterations() {
    local n=${#EXP_CMDS[@]} i max=5
    printf '  %s↻%s %s%d itération%s%s\n' \
           "$MAGENTA" "$C0" "$GRAS" "$n" "$(pluriel "$n")" "$C0"
    for (( i = 0; i < n && i < max; i++ )); do
        printf '    %s·%s %s\n' "$ESTOMPE" "$C0" "${EXP_LABELS[$i]}"
    done
    (( n > max )) && printf '    %s… et %d autres (l pour tout voir)%s\n' "$ESTOMPE" $(( n - max )) "$C0"
    (( EXP_TRONQUE )) && attention "limite de $MAX_ITERATIONS itérations atteinte : la liste est tronquée (MAX_ITERATIONS en section 1)"
}

lister_iterations() {
    local i
    for i in "${!EXP_CMDS[@]}"; do
        printf '    %s%3d%s %s\n' "$GRAS" $(( i + 1 )) "$C0" "${EXP_LABELS[$i]}"
        printf '        %s%s%s\n' "$ESTOMPE" "${EXP_CMDS[$i]}" "$C0"
    done
}


# --- Exécution d'un groupe d'itérations ------------------------------
# Une étape simple est un groupe d'une itération : un seul chemin de
# code, donc un seul endroit où se tromper.
G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_DUREE=0; G_RC=0
executer_groupe() {
    local une_par_une="$1"
    local n=${#EXP_CMDS[@]} i rc choix ignorer=0 debut=$SECONDS
    local multiple=0
    (( n > 1 )) && multiple=1

    G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_RC=0

    for i in "${!EXP_CMDS[@]}"; do
        if (( multiple )); then
            printf '\n  %s├─ [%d/%d]%s %s%s%s\n' \
                   "$ESTOMPE" $(( i + 1 )) "$n" "$C0" "$MAGENTA" "${EXP_LABELS[$i]}" "$C0"
            printf '  %s│%s  ' "$ESTOMPE" "$C0"
            afficher_commande "${EXP_CMDS[$i]}"
        fi

        if (( une_par_une )); then
            choix=""
            printf '  %sEntrée exécuter · p passer · t tout enchaîner · q arrêter la boucle%s\n' "$ESTOMPE" "$C0"
            lire "  ${GRAS}>${C0} " choix || abandon
            case "${choix,,}" in
                p) printf '  %s⏭️  passée%s\n' "$ESTOMPE" "$C0"; G_SKIP=$(( G_SKIP + 1 )); continue ;;
                q) printf '  %sboucle arrêtée%s\n' "$JAUNE" "$C0"; break ;;
                t) une_par_une=0 ;;
            esac
        fi

        executer_une "${EXP_CMDS[$i]}" "$F_LOG"
        rc=$?

        if (( INTERROMPU )); then
            printf '  %s⚠️  interrompu au bout de %s%s\n' "$JAUNE" "$(duree $DUREE_S)" "$C0"
            G_INT=$(( G_INT + 1 ))
            if (( multiple )); then
                demander_oui_non "  Continuer la boucle ? [O/n] : " || { G_ARRET=1; break; }
                continue
            fi
            break
        fi

        if (( rc == 0 )); then
            if [[ "$SIMULATION" == "true" ]]; then
                printf '  %s👁️  simulée%s\n' "$BLEU" "$C0"
            else
                printf '  %s✅ %s%s\n' "$VERT" "$(duree $DUREE_S)" "$C0"
            fi
            G_OK=$(( G_OK + 1 ))
            continue
        fi

        printf '  %s❌ code %d, %s%s\n' "$ROUGE" "$rc" "$(duree $DUREE_S)" "$C0"
        G_KO=$(( G_KO + 1 )); G_RC=$rc

        (( F_CONTINU )) && continue
        if (( F_STOP )); then
            erreur "étape marquée « stop » : arrêt du script."
            G_ARRET=2; break
        fi
        (( ignorer )) && continue

        if (( multiple )); then
            choix=""
            printf '  %sEntrée continuer · t continuer sans redemander · n arrêter la boucle · q quitter%s\n' "$ESTOMPE" "$C0"
            lire "  ${GRAS}>${C0} " choix || abandon
            case "${choix,,}" in
                t)   ignorer=1 ;;
                n)   G_ARRET=1; break ;;
                q)   G_ARRET=2; break ;;
            esac
        else
            demander_oui_non "  Continuer quand même ? [O/n] : " || G_ARRET=2
        fi
    done

    G_DUREE=$(( SECONDS - debut ))
    return 0
}


# --- Boucle principale -----------------------------------------------
TOTAL=${#COMMANDES[@]}
NUM=0
NB_FILTREES=0

for entree in "${COMMANDES[@]}"; do
    NUM=$(( NUM + 1 ))

    # Découpage en trois champs sur les deux premiers séparateurs.
    TITRE="${entree%%|*}"
    RESTE="${entree#*|}"
    analyser_validation "${RESTE%%|*}"
    BRUTE="${RESTE#*|}"

    if ! etape_retenue "$NUM"; then
        NB_FILTREES=$(( NB_FILTREES + 1 ))
        continue
    fi

    CLE="$(empreinte "$TITRE|$BRUTE")"
    if deja_faite "$CLE"; then
        titre_etape "$NUM" "$TOTAL" "$TITRE"
        info "déjà réussie précédemment — sautée (--reprendre)"
        RECAP+=("skip|reprise|$TITRE")
        NB_PASSEES=$(( NB_PASSEES + 1 ))
        continue
    fi

    titre_etape "$NUM" "$TOTAL" "$TITRE"

    resoudre_simples "$BRUTE"     # demande les [[valeurs]] manquantes
    CMDBASE="$CMD"                # recopié tout de suite : expanser écrase CMD
    BESOIN_EXP=1

    # Boucle interne : on y revient après une édition, on en sort après
    # une exécution ou un saut.
    while true; do

        if (( BESOIN_EXP )); then
            # Le message d'attente s'efface avec un \r : hors terminal
            # (sortie redirigée) il resterait collé à la ligne suivante,
            # donc on ne l'affiche que si l'on parle bien à un écran.
            if [[ "$CMDBASE" == *"{{"* && -t 1 ]]; then
                printf '  %s... lecture des listes%s' "$ESTOMPE" "$C0"
                expanser "$CMDBASE"; RCEXP=$?
                printf '\r%s\r' "$(repeter ' ' 26)"
            else
                expanser "$CMDBASE"; RCEXP=$?
            fi
            BESOIN_EXP=0

            if (( RCEXP != 0 )) || (( ${#EXP_CMDS[@]} == 0 )); then
                erreur "les listes de cette étape n'ont rien donné : étape impossible."
                RECAP+=("ko|liste vide|$TITRE")
                NB_KO=$(( NB_KO + 1 ))
                if [[ "$INTERACTIF" == "oui" && "$SANS_QUESTION" != "true" ]]; then
                    printf '  %sEntrée passer à la suite · r ressaisir les valeurs · q quitter%s\n' "$ESTOMPE" "$C0"
                    CHOIX=""
                    lire "  ${GRAS}>${C0} " CHOIX || abandon
                    case "${CHOIX,,}" in
                        r) for k in ${PH_SIMPLES[@]+"${PH_SIMPLES[@]}"}; do unset "REPONSES[$k]"; done
                           CACHE_LISTE=(); resoudre_simples "$BRUTE"; CMDBASE="$CMD"; BESOIN_EXP=1; continue ;;
                        q) printf 'Arrêt demandé.\n'; exit 1 ;;
                    esac
                fi
                break
            fi
        fi

        N=${#EXP_CMDS[@]}
        REPETEE=0
        (( N > 1 )) && REPETEE=1
        [[ -n "${EXP_LABELS[0]}" ]] && REPETEE=1

        if (( REPETEE )); then
            resume_iterations
        else
            afficher_commande "${EXP_CMDS[0]}"
        fi

        # Un CHOIX vide vaut « exécuter » : c'est ce qui rend les étapes
        # validation=false automatiques, sans rien demander.
        CHOIX=""
        if [[ "$F_VALIDER" == "true" || "$TOUT_VALIDER" == "true" ]]; then
            if (( REPETEE )); then
                printf '  %sEntrée tout exécuter · u une par une · l lister · p passer · e éditer · r ressaisir · q quitter%s\n' "$ESTOMPE" "$C0"
            else
                printf '  %sEntrée exécuter · p passer · e éditer · r ressaisir · s voir en clair · q quitter%s\n' "$ESTOMPE" "$C0"
            fi
            lire "  ${GRAS}>${C0} " CHOIX || abandon
        fi

        case "${CHOIX,,}" in
            ""|o|y|u|t)
                UNE_PAR_UNE=0
                [[ "${CHOIX,,}" == "u" ]] && UNE_PAR_UNE=1
                executer_groupe "$UNE_PAR_UNE"

                if (( REPETEE )); then
                    # Bilan agrégé : une ligne de récapitulatif par étape,
                    # même si elle a tourné trois cents fois.
                    DETAIL="$G_OK/$N ok"
                    (( G_SKIP )) && DETAIL+=" ${G_SKIP}skip"
                    if [[ "$SIMULATION" == "true" ]]; then
                        RECAP+=("sim|$N iter|$TITRE")
                    elif (( G_KO == 0 && G_INT == 0 && G_SKIP == 0 )); then
                        RECAP+=("ok|$G_OK/$N $(duree $G_DUREE)|$TITRE")
                        NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"
                    elif (( G_KO > 0 )); then
                        RECAP+=("ko|$G_KO KO /$N|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                    else
                        RECAP+=("int|$DETAIL|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 ))
                    fi
                    printf '\n  %s└─%s %s%d réussie%s%s · %s%d échec%s%s · %s%d passée%s%s · %s\n' \
                           "$ESTOMPE" "$C0" \
                           "$VERT"    "$G_OK"   "$(pluriel "$G_OK")"   "$C0" \
                           "$ROUGE"   "$G_KO"   "$(pluriel "$G_KO")"   "$C0" \
                           "$ESTOMPE" "$G_SKIP" "$(pluriel "$G_SKIP")" "$C0" \
                           "$(duree $G_DUREE)"
                else
                    if (( G_INT )); then
                        RECAP+=("int|$(duree $G_DUREE)|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 ))
                        if (( ! G_ARRET )); then
                            demander_oui_non "  Passer à l'étape suivante ? [O/n] : " \
                                || { printf 'Arrêt.\n'; exit 130; }
                        fi
                    elif (( G_KO )); then
                        RECAP+=("ko|code $G_RC|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                    elif [[ "$SIMULATION" == "true" ]]; then
                        RECAP+=("sim|simulee|$TITRE")
                    else
                        RECAP+=("ok|$(duree $G_DUREE)|$TITRE")
                        NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"
                    fi
                fi

                (( G_ARRET == 2 )) && { printf '\nArrêt.\n'; exit 1; }
                break
                ;;

            l)
                lister_iterations
                ;;

            s)
                afficher_commande_lisible "${EXP_CMDS[0]}"
                ;;

            p)
                printf '  %s⏭️  passée%s\n' "$ESTOMPE" "$C0"
                RECAP+=("skip|passee|$TITRE")
                NB_PASSEES=$(( NB_PASSEES + 1 ))
                journal "PASSÉE : $TITRE"
                break
                ;;

            e)
                # Modification ponctuelle, non enregistrée dans le tableau.
                # On repasse par la résolution au cas où l'édition ajoute
                # un [[nom]] ou un {{nom}}.
                info "édition — la modification ne vaut que pour cette exécution"
                lire_edit "$CMDBASE" CMDBASE
                resoudre_simples "$CMDBASE"
                CMDBASE="$CMD"
                BESOIN_EXP=1
                ;;

            r)
                # Un chiffre oublié dans l'offset ? On repart des questions,
                # mais seulement pour les valeurs de CETTE étape : effacer
                # tout obligerait à ressaisir ce qui était juste.
                CMDTMP="$BRUTE"
                while [[ "$CMDTMP" =~ $RE_SIMPLE ]]; do
                    NOMTMP="${BASH_REMATCH[1]}"
                    unset "REPONSES[$NOMTMP]"
                    CMDTMP="${CMDTMP//\[\[$NOMTMP\]\]/}"
                done
                CACHE_LISTE=()          # les listes en dépendaient
                resoudre_simples "$BRUTE"
                CMDBASE="$CMD"
                BESOIN_EXP=1
                info "valeurs ressaisies"
                ;;

            q)
                printf 'Arrêt demandé.\n'
                exit 0
                ;;

            *)
                printf '  %schoix inconnu%s\n' "$JAUNE" "$C0"
                ;;
        esac
    done
done

(( NB_FILTREES > 0 )) && info "$NB_FILTREES étape(s) écartée(s) par --seulement / --depuis"

# Le code de sortie sert à enchaîner : 0 si tout est passé, 1 s'il reste
# une étape en échec — même si vous avez choisi de continuer sur le coup.
(( NB_KO > 0 )) && exit 1
exit 0
