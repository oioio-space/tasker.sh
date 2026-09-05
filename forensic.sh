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
# 2 bis. MODE DÉMONSTRATION  (./forensic.sh --demo)
#
# Le même moteur, mais sur un bac à sable fabriqué dans /tmp et avec des
# commandes que tout le monde a : ls, wc, sha256sum. Aucune image disque,
# aucun outil forensique, rien à installer. C'est le meilleur endroit
# pour comprendre [[valeur]], {{liste}} et l'emboîtement avant de
# toucher à de vrais scellés.
#
# Lisez ce bloc en parallèle du vrai tableau, plus haut : il est
# volontairement écrit de la même façon.
# =====================================================================
definir_commandes_demo() {

COMMANDES=(

# 1. Une étape toute simple. Pas de validation : elle s'exécute seule.
"Ce qu'il y a dans le bac à sable|false|ls -R '$DEMO_RACINE'"

# 2. [[service]] : une valeur demandée UNE fois puis réutilisée.
#    Comme la liste « service » existe plus bas, la question devient un
#    menu numéroté. Essayez aussi « a » (autre valeur) et « p » (passer).
"Contenu d'un service|true|ls -l '$DEMO_RACINE/[[service]]'"

# 3. La même [[valeur]] : elle n'est plus redemandée.
"Taille de ce service|true|du -sh '$DEMO_RACINE/[[service]]'"

# 4. {{agent}} : l'étape est REJOUÉE une fois par agent du service
#    choisi. Regardez le nombre d'itérations annoncé avant de valider,
#    et essayez « u » pour les dérouler une par une, « l » pour les voir.
#    {{agent}} vaut le chemin, {{agent_libelle}} le nom seul.
"Nombre de fichiers par agent|true|echo -n '{{agent_libelle}} : '; ls -1 '{{agent}}' | wc -l"

# 5. Deux listes emboîtées, mais une seule est écrite : la liste
#    « note » a besoin de {{agent}}, donc la boucle sur les agents se
#    déclenche toute seule. C'est la « commande récursive ».
#    {{note_libelle}} donne le nom lisible de la même valeur.
"Empreinte de chaque note de chaque agent|true,log|sha256sum '{{note}}'"

# 6. Une étape qui échoue, pour voir ce que fait le script.
#    L'option « continu » lui dit de ne pas poser de question.
"Une étape qui échoue exprès|true,continu|ls '$DEMO_RACINE/ce-fichier-n-existe-pas'"

# 7. Une commande sur plusieurs instructions : au-delà de deux ou trois,
#    écrivez plutôt une fonction en section 3.
"Compte-rendu|false,log|printf 'services : %s\n' \$(ls '$DEMO_RACINE' | wc -l); printf 'notes    : %s\n' \$(find '$DEMO_RACINE' -name '*.txt' | wc -l)"

)

LISTES=(

# Une liste = un nom, et une commande qui écrit une valeur par ligne.
"service|ls -1 '$DEMO_RACINE'"

# Celle-ci dépend de [[service]] : elle sera régénérée si vous
# ressaisissez la valeur avec « r ».
"agent|lister_agents '$DEMO_RACINE/[[service]]'"

# Celle-ci dépend de {{agent}} : c'est ce qui crée l'emboîtement.
# Chaque ligne est « chemin<TAB>libellé » : la commande reçoit le
# chemin, vous lisez le libellé.
"note|lister_notes '{{agent}}'"

)
}

# Fabrique le bac à sable. Idempotent : relancer --demo ne casse rien.
preparer_demo() {
    local a n
    mkdir -p "$DEMO_RACINE" || return 1
    for a in comptabilite/alice comptabilite/bruno "logistique/celia dupont" logistique/omar; do
        mkdir -p "$DEMO_RACINE/$a"
        for n in memo rapport; do
            printf 'note %s de %s\nligne 2\n' "$n" "${a##*/}" > "$DEMO_RACINE/$a/$n.txt"
        done
    done
    # Un nom avec une apostrophe : c'est exactement ce qui casse les
    # scripts écrits trop vite, et ce que le script doit encaisser.
    mkdir -p "$DEMO_RACINE/logistique/o'brien"
    printf 'note avec une apostrophe dans le chemin\n' > "$DEMO_RACINE/logistique/o'brien/memo.txt"
    return 0
}

# lister_agents <dossier> : les sous-dossiers, « chemin<TAB>nom ».
# Écrire une fonction plutôt qu'une ligne de find + sed illisible : c'est
# le conseil de la section 3, appliqué ici.
lister_agents() {
    local d="$1" a
    for a in "$d"/*/; do
        (( INTERROMPU )) && return 130
        [[ -d "$a" ]] || continue
        a="${a%/}"
        printf '%s\t%s\n' "$a" "${a##*/}"
    done
    return 0
}

# lister_notes <dossier> : les .txt d'un agent, « chemin<TAB>libellé ».
lister_notes() {
    local d="$1" f
    for f in "$d"/*.txt; do
        (( INTERROMPU )) && return 130
        [[ -e "$f" ]] || continue
        printf '%s\t%s\n' "$f" "${f##*/}"
    done
    return 0
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

# Sous une locale POSIX, printf et ${#var} comptent les OCTETS : « é »
# en vaut deux et toute colonne alignée se décale. On mesure donc la
# largeur réelle, ce qui permet d'aligner des titres accentués — et donc
# d'avoir une arborescence propre plutôt que des colonnes en escalier.
_SONDE="é"
UTF8_OK=0
(( ${#_SONDE} == 1 )) && UTF8_OK=1
unset _SONDE

largeur_texte() {
    if (( UTF8_OK )); then
        printf '%s' "${#1}"
    else
        # On retire les octets de continuation UTF-8 (0x80–0xBF) : ce qui
        # reste, c'est un octet par caractère.
        local t="${1//[$'\x80'-$'\xbf']/}"
        printf '%s' "${#t}"
    fi
}

# pad_droite <texte> <largeur> : le texte, complété par des espaces.
# Un texte plus long que la colonne n'est pas coupé — mieux vaut une
# ligne qui dépasse qu'un nom de fichier tronqué au mauvais endroit.
pad_droite() {
    local t="$1" l="$2" n
    n=$(( l - $(largeur_texte "$t") ))
    (( n < 0 )) && n=0
    printf '%s%s' "$t" "$(repeter ' ' "$n")"
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

 POUR COMPRENDRE, SANS RISQUE
     ./forensic.sh --demo              bac à sable dans /tmp : aucune image
                                       disque, aucun outil forensique, les
                                       mêmes mécanismes. Les étapes de la
                                       démonstration sont en section 2 bis
                                       du script, commentées une à une.

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

 LECTURE DE L'ÉCRAN
     Le plan est affiché au démarrage, le récapitulatif à la sortie ;
     les deux emploient les mêmes marques, et les itérations d'une étape
     répétée apparaissent en dessous d'elle, comme des sous-tâches :

         ○  à faire        ◐  en cours       ●  réussie
         ✗  échec          ⊘  passée         ⊗  interrompue
         ◌  simulée (-n)

         ●  6  Inventaire par utilisateur              3/3  4s
             ├─ ●  home=Users/alice                          1s
             ├─ ●  home=Users/bruno                          2s
             └─ ✗  home=Users/celia                     code 1

 À CHAQUE ÉTAPE
     Entrée  exécuter        p  passer cette étape
     e       éditer la ligne r  ressaisir les [[valeurs]] de l'étape
     q       arrêter le script
     Sur une étape répétée s'ajoutent :
     u       exécuter une itération à la fois (validation de chacune)
     l       lister les itérations prévues avec leur commande
     Quand le script demande une [[valeur]] :
     1 2 3   choisir dans la liste proposée
     a       saisir une autre valeur
     p       passer cette étape               q  quitter le script
     (après « a », p et q redeviennent des valeurs ordinaires)

     Ctrl-C  pendant une COMMANDE : interrompt cette commande, et le
             script vous demande si vous continuez avec la suivante ;
             pendant une QUESTION : arrête le script proprement, avec
             le récapitulatif et le rapport.
     Ctrl-D  à une question : plus personne au clavier, le script
             s'arrête plutôt que d'inventer une réponse.

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
DEMO="false"
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
        --demo)           DEMO="true";            shift ;;
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

# Mode démonstration : on remplace le poste analysé par un bac à sable
# fabriqué dans /tmp, et le tableau de commandes par celui de la
# section 2 bis. Tout le reste du script est identique — c'est bien le
# but : ce que vous apprenez ici vaut pour une vraie analyse.
if [[ "$DEMO" == "true" ]]; then
    DEMO_RACINE="${TMPDIR:-/tmp}/forensic-demo/scelles"
    PC="DEMO"; SALLE="bac-a-sable"; OS="demo"
    BASE="${TMPDIR:-/tmp}/forensic-demo/sortie"
    REQUIS=(ls find wc du sha256sum)
    calculer_chemins
    preparer_demo || { printf 'ERREUR : bac à sable impossible à créer.\n' >&2; exit 1; }
    definir_commandes_demo
else
    calculer_chemins
    definir_commandes
fi


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

# fin_entree : plus personne au clavier (Ctrl-D, ou une entrée redirigée
# qui s'épuise). Toute question suivante serait sans réponse : inventer
# une valeur ici enverrait une commande amputée sur les scellés.
fin_entree() {
    printf '\n'
    erreur "fin de l'entrée clavier (Ctrl-D) — arrêt."
    journal "ARRÊT : fin de l'entrée clavier"
    exit 130
}

# lire <invite> <nom_variable>
# Renvoie toujours 0 : une réponse vide vaut « la proposition par défaut ».
# Les deux façons de ne pas répondre sont traitées ailleurs, et pas de la
# même manière : Ctrl-D coupe l'entrée (fin_entree), Ctrl-C arrête le
# script proprement (voir gerer_int, plus bas).
lire() {
    local invite="$1" cible="$2" rc

    if [[ "$SANS_QUESTION" == "true" ]]; then
        printf -v "$cible" '%s' ""       # comme si on avait tapé Entrée
        printf '%s%s[-y]%s\n' "$invite" "$ESTOMPE" "$C0"
        return 0
    fi

    EN_SAISIE=1
    # shellcheck disable=SC2229   # $cible est un NOM de variable, pas sa valeur
    read -r -p "$invite" "$cible" < "$ENTREE"; rc=$?
    EN_SAISIE=0
    (( rc != 0 )) && fin_entree
    return 0
}

# lire_edit <valeur_initiale> <nom_variable> : ligne pré-remplie, modifiable
lire_edit() {
    EN_SAISIE=1
    read -r -e -i "$1" -p "  ${CYAN}\$${C0} " "$2" < "$ENTREE" || true
    EN_SAISIE=0
}

# demander_oui_non <invite> : vrai si l'utilisateur accepte (défaut oui)
demander_oui_non() {
    local r=""
    lire "$1" r
    case "${r,,}" in n|non|q) return 1 ;; *) return 0 ;; esac
}

# --- Récapitulatif ---------------------------------------------------
# Une ligne par étape traitée : "code|détail|titre". Rempli au fil de
# l'eau, affiché à la sortie du script — y compris sur un arrêt anticipé
# (q, Ctrl-C), d'où le trap EXIT.
RECAP=()                    # "etat|detail|titre" — une entrée par étape
declare -A ENFANTS=()       # numéro d'étape -> itérations, séparées par \x01
NB_OK=0; NB_KO=0; NB_PASSEES=0

# L'état d'une étape se lit à la forme du cercle, pas à sa couleur :
#   ○ à faire   ◐ en cours   ● réussie
#   ✗ échec     ⊘ passée     ⊗ interrompue     ◌ simulée
# Un seul caractère de large chacun, et aucun emoji : les emoji occupent
# deux cellules — parfois une et demie selon le terminal — et toute
# colonne alignée s'effondre.
glyphe() {
    case "$1" in
        todo)  printf '%s○%s' "$ESTOMPE" "$C0" ;;
        cours) printf '%s◐%s' "$CYAN"    "$C0" ;;
        ok)    printf '%s●%s' "$VERT"    "$C0" ;;
        ko)    printf '%s✗%s' "$ROUGE"   "$C0" ;;
        skip)  printf '%s⊘%s' "$ESTOMPE" "$C0" ;;
        int)   printf '%s⊗%s' "$JAUNE"   "$C0" ;;
        sim)   printf '%s◌%s' "$BLEU"    "$C0" ;;
        *)     printf ' ' ;;
    esac
}

# Le même, en texte, pour le rapport écrit sur disque.
glyphe_texte() {
    case "$1" in
        todo) printf 'a faire' ;;  cours) printf 'en cours' ;;
        ok)   printf 'ok'      ;;  ko)    printf 'ECHEC'    ;;
        skip) printf 'passee'  ;;  int)   printf 'interrompue' ;;
        sim)  printf 'simulee' ;;  *)     printf '?' ;;
    esac
}

# LARGEUR_TITRE : la colonne où tiennent les titres. Le détail (durée,
# code d'erreur) est ensuite aligné à droite de cette colonne.
colonne_titre() {
    local l=$(( LARGEUR - 22 ))
    (( l < 24 )) && l=24
    (( l > 52 )) && l=52
    printf '%s' "$l"
}

# ligne_tache <état> <numéro|""> <titre> <détail>
#     ●  4  Inventaire par utilisateur          3/3  2s
ligne_tache() {
    local etat="$1" num="$2" titre="$3" detail="$4"
    # Sans détail, pas de bourrage : une ligne ne doit pas traîner
    # d'espaces jusqu'au bord de l'écran.
    [[ -n "$detail" ]] || { printf '  %s %s%2s%s  %s\n' \
        "$(glyphe "$etat")" "$ESTOMPE" "$num" "$C0" "$titre"; return 0; }
    if [[ -n "$num" ]]; then
        printf '  %s %s%2s%s  %s  %s%s%s\n' \
               "$(glyphe "$etat")" "$ESTOMPE" "$num" "$C0" \
               "$(pad_droite "$titre" "$(colonne_titre)")" \
               "$ESTOMPE" "$detail" "$C0"
    else
        printf '  %s      %s  %s%s%s\n' \
               "$(glyphe "$etat")" \
               "$(pad_droite "$titre" "$(colonne_titre)")" \
               "$ESTOMPE" "$detail" "$C0"
    fi
}

# --- Plan de départ ---------------------------------------------------
# Toutes les étapes, en attente. On sait d'un coup d'œil ce qui va se
# passer, dans quel ordre, et lesquelles vont poser une question.
plan_initial() {
    local avec_cmd="${1:-non}"
    local i=0 e reste marques
    printf '\n'
    regle "$GRAS"
    printf ' %sPlan%s   %s%d étape%s%s\n' "$GRAS" "$C0" "$ESTOMPE" "$TOTAL" "$(pluriel "$TOTAL")" "$C0"
    regle "$GRAS"
    for e in "${COMMANDES[@]}"; do
        i=$(( i + 1 ))
        reste="${e#*|}"
        analyser_validation "${reste%%|*}"

        # On ne signale que ce qui sort de l'ordinaire : « auto » (l'étape
        # part sans rien demander) plutôt que « confirmation », qui est le
        # cas courant et n'apprendrait rien.
        marques=""
        _m() { marques+="${marques:+ · }$1"; }
        [[ "${reste#*|}" == *"{{"* ]] && _m "↻ répétée"
        [[ "$F_VALIDER" == "false" && "$TOUT_VALIDER" != "true" ]] && _m "auto"
        (( F_LOG ))     && _m "log"
        (( F_STOP ))    && _m "stop"
        (( F_CONTINU )) && _m "continu"
        unset -f _m

        if etape_retenue "$i"; then
            ligne_tache todo "$i" "${e%%|*}" "$marques"
        else
            ligne_tache skip "$i" "${e%%|*}" "hors filtre"
        fi
        [[ "$avec_cmd" == "oui" ]] && afficher_commande "${reste#*|}" "        "
    done
    regle
    return 0
}

# --- Récapitulatif ---------------------------------------------------
# Rempli au fil de l'eau, affiché à la sortie du script — y compris sur
# un arrêt anticipé (q, Ctrl-C), d'où le trap EXIT. Les étapes répétées
# montrent leurs itérations en dessous, comme les sous-tâches d'une tâche.
recap() {
    (( ${#RECAP[@]} == 0 )) && return
    local l e d t num=0

    printf '\n'
    regle "$GRAS"
    printf ' %sRécapitulatif%s   %s%s · %s · %s%s\n' \
           "$GRAS" "$C0" "$ESTOMPE" "$PC" "$SALLE" "$OS" "$C0"
    regle "$GRAS"

    for l in "${RECAP[@]}"; do
        num="${l%%|*}";  l="${l#*|}"
        e="${l%%|*}";    l="${l#*|}"
        d="${l%%|*}";    t="${l#*|}"
        ligne_tache "$e" "$num" "$t" "$d"
        recap_enfants "$num"
    done

    regle
    printf '  %s%d réussie%s%s · %s%d en échec%s · %s%d passée%s%s · total %s\n' \
           "$VERT"    "$NB_OK"      "$(pluriel "$NB_OK")"      "$C0" \
           "$ROUGE"   "$NB_KO"      "$C0" \
           "$ESTOMPE" "$NB_PASSEES" "$(pluriel "$NB_PASSEES")" "$C0" \
           "$(duree "$SECONDS")"
    printf '  %sjournal  %s%s\n' "$ESTOMPE" "$LOG" "$C0"

    ecrire_rapport
}

# recap_enfants <numéro d'étape> : les itérations, en arborescence.
# Au-delà de dix, on ne montre que ce qui a mal tourné : une étape jouée
# trois cents fois n'a pas sa place en entier dans un récapitulatif.
recap_enfants() {
    local cle="$1" brut=""
    brut="${ENFANTS[$cle]:-}"
    [[ -n "$brut" ]] || return 0

    local -a lignes=()
    mapfile -t lignes < <(printf '%s' "${brut//$'\x01'/$'\n'}")

    local n=${#lignes[@]} i etat det etiq branche montre=0 caches=0
    (( n <= 10 )) && montre=1

    for i in "${!lignes[@]}"; do
        [[ -n "${lignes[$i]}" ]] || continue
        etat="${lignes[$i]%%|*}"; det="${lignes[$i]#*|}"
        etiq="${det#*|}"; det="${det%%|*}"
        if (( ! montre )) && [[ "$etat" == "ok" ]]; then
            caches=$(( caches + 1 )); continue
        fi
        if (( i == n - 1 )); then branche="└─"; else branche="├─"; fi
        printf '      %s%s%s %s %s  %s%s%s\n' \
               "$ESTOMPE" "$branche" "$C0" "$(glyphe "$etat")" \
               "$(pad_droite "$etiq" $(( $(colonne_titre) - 3 )))" \
               "$ESTOMPE" "$det" "$C0"
    done
    (( caches > 0 )) && printf '      %s   … et %d itération%s réussie%s%s\n' \
                               "$ESTOMPE" "$caches" "$(pluriel "$caches")" "$(pluriel "$caches")" "$C0"
    return 0
}

# Le rapport est la trace qu'on garde : il doit survivre à la fermeture
# du terminal, et rester lisible sans couleur ni caractère exotique.
ecrire_rapport() {
    [[ -n "${DIR_LOGS:-}" && -d "${DIR_LOGS:-}" ]] || return 0
    local f="$DIR_LOGS/${PREFIX}_rapport.txt" l e d t num brut ligne

    {
        printf 'Rapport forensic.sh\n'
        printf '  poste      %s / %s / %s\n' "$PC" "$SALLE" "$OS"
        printf '  image      %s\n' "$IMAGE"
        printf '  analyste   %s\n' "$OPERATEUR"
        printf '  machine    %s\n' "$(hostname 2>/dev/null || printf inconnue)"
        printf '  debut      %s\n' "$DEBUT_HORODATE"
        printf '  fin        %s\n' "$(date '+%F %T %z')"
        printf '  duree      %s\n' "$(duree "$SECONDS")"
        printf '\n'
        for l in "${RECAP[@]}"; do
            num="${l%%|*}";  l="${l#*|}"
            e="${l%%|*}";    l="${l#*|}"
            d="${l%%|*}";    t="${l#*|}"
            printf '  %2s  %-12s %-10s %s\n' "$num" "$(glyphe_texte "$e")" "$d" "$t"
            brut="${ENFANTS[$num]:-}"
            if [[ -n "$brut" ]]; then
                while IFS= read -r ligne; do
                    [[ -n "$ligne" ]] || continue
                    e="${ligne%%|*}"; d="${ligne#*|}"; t="${d#*|}"; d="${d%%|*}"
                    printf '        %-12s %-10s %s\n' "$(glyphe_texte "$e")" "$d" "$t"
                done <<< "${brut//$'\x01'/$'\n'}"
            fi
        done
        printf '\n  %d reussies, %d en echec, %d passees\n' "$NB_OK" "$NB_KO" "$NB_PASSEES"
    } > "$f" 2>/dev/null && printf '  %srapport  %s%s\n' "$ESTOMPE" "$f" "$C0"
}

LOG="/dev/null"
DEBUT_HORODATE="$(date '+%F %T %z')"
trap recap EXIT

# Ctrl-C : deux situations, deux réponses.
#
#   pendant une commande  -> on interrompt cette commande-là, pas le
#     script. Bash met le gestionnaire en attente tant qu'une commande
#     tourne au premier plan : le signal atteint d'abord la commande,
#     puis on reprend la main ici et INTERROMPU vaut 1.
#
#   pendant une question  -> on arrête le script, proprement, avec le
#     récapitulatif. Sans ce cas particulier, la surprise est totale :
#     bash n'interrompt PAS un « read » sur un signal simplement piégé,
#     il exécute le gestionnaire et retourne attendre. L'écran affiche
#     « ^C » et plus rien ne se passe — le script paraît figé alors qu'il
#     attend toujours la réponse.
#
# EN_SAISIE dit laquelle des deux situations est en cours.
INTERROMPU=0
EN_SAISIE=0
gerer_int() {
    if (( EN_SAISIE )); then
        EN_SAISIE=0
        printf '\n'
        attention "interruption au clavier — arrêt."
        journal "ARRÊT : Ctrl-C pendant une question"
        exit 130
    fi
    INTERROMPU=1
}
trap gerer_int INT

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

    # 1. Valeurs imposées par --liste : rien à exécuter.
    if [[ -n "${LISTE_FIGEE[$nom]:-}" ]]; then
        VALEURS=(); LIBELLES=()
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
        # Le message d'attente est affiché ici et pas dans la boucle
        # principale : la résolution ci-dessus peut ouvrir un menu, et
        # le message se serait intercalé au milieu. Il ne s'affiche que
        # sur un vrai terminal, seul endroit où le \r efface la ligne.
        if [[ -t 1 ]]; then
            printf '  %s… lecture de la liste « %s »%s' "$ESTOMPE" "$nom" "$C0"
            sortie="$(eval "$gen" 2>> "$LOG")"
            rc=$?
            printf '\r%s\r' "$(repeter ' ' $(( ${#nom} + 30 )))"
        else
            sortie="$(eval "$gen" 2>> "$LOG")"
            rc=$?
        fi
        if (( rc != 0 && ${#sortie} == 0 )); then
            erreur "la liste « $nom » a échoué (code $rc) — voir $LOG"
            return 1
        fi
        CACHE_LISTE["$gen"]="${sortie:-$'\001vide'}"
    fi

    # 4. Une ligne = une valeur, éventuellement "valeur<TAB>libellé".
    #
    #    La remise à zéro est ICI, et surtout pas au début de la
    #    fonction : l'étape 2 ci-dessus peut relancer generer_liste pour
    #    une AUTRE liste (celle-ci a besoin d'un [[nom]] qui vient
    #    lui-même d'un menu). Vidé trop tôt, VALEURS se retrouverait à
    #    contenir les valeurs des deux listes bout à bout.
    VALEURS=(); LIBELLES=()
    while IFS= read -r ligne; do
        [[ -z "$ligne" ]] && continue
        if [[ "$ligne" == *$'\t'* ]]; then
            val="${ligne%%$'\t'*}"; lib="${ligne#*$'\t'}"
        else
            val="$ligne"; lib=""
        fi
        # Une valeur qui contient [[ ou {{ serait redétectée comme un
        # placeholder après substitution, et la boucle repartirait sur
        # elle-même. Cas rarissime, mais silencieux : on le dit.
        if [[ "$val" == *'[['* || "$val" == *'{{'* ]]; then
            attention "valeur ignorée dans « $nom » (elle contient [[ ou {{) : $val"
            continue
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

# ou_sert <nom> : « étapes 2, 3, 6 », pour que l'on sache ce qu'on remplit
ou_sert() {
    local i
    for i in ${PH_SIMPLES[@]+"${!PH_SIMPLES[@]}"}; do
        [[ "${PH_SIMPLES[$i]}" == "$1" ]] && { printf '%s' "${USAGE_SIMPLES[$i]}"; return 0; }
    done
    return 0
}

# demander_valeur <nom> -> VALEUR
#   0  une valeur a été obtenue
#   1  l'utilisateur demande à passer l'étape
#
# Menu numéroté si une liste du même nom existe, saisie libre sinon.
# Un menu vaut mieux qu'une question ouverte : l'offset d'une partition
# ne se devine pas, et le recopier à la main est la première source
# d'erreur de toute la chaîne.
VALEUR=""
demander_valeur() {
    local nom="$1" i n choix ou libre=0
    local -a v=() l=()

    if [[ -n "${GENERATEUR[$nom]:-}" || -n "${LISTE_FIGEE[$nom]:-}" ]]; then
        if generer_liste "$nom"; then
            v=("${VALEURS[@]}"); l=("${LIBELLES[@]}")
        fi
    fi
    INTERROMPU=0        # une liste interrompue ne doit pas polluer la suite

    ou="$(ou_sert "$nom")"
    n=${#v[@]}

    if (( n > 0 )); then
        printf '\n    %s┌─%s %s[[%s]]%s%s%s\n' "$BLEU" "$C0" "$GRAS$CYAN" "$nom" "$C0" \
               "$ESTOMPE" "${ou:+  — sert aux étapes $ou}"
        printf '    %s│%s\n' "$BLEU" "$C0"
        for i in "${!v[@]}"; do
            if [[ -n "${l[$i]}" ]]; then
                printf '    %s│%s  %s%2d%s  %s%-14s%s %s%s%s\n' \
                       "$BLEU" "$C0" "$GRAS" $(( i + 1 )) "$C0" \
                       "$VERT" "${v[$i]}" "$C0" "$ESTOMPE" "${l[$i]}" "$C0"
            else
                printf '    %s│%s  %s%2d%s  %s%s%s\n' \
                       "$BLEU" "$C0" "$GRAS" $(( i + 1 )) "$C0" "$VERT" "${v[$i]}" "$C0"
            fi
        done
        printf '    %s│%s\n' "$BLEU" "$C0"
        printf '    %s│%s  %s a%s  %ssaisir une autre valeur%s\n'  "$BLEU" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
        printf '    %s│%s  %s p%s  %spasser cette étape%s\n'        "$BLEU" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
        printf '    %s│%s  %s q%s  %squitter le script%s\n'         "$BLEU" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"

        while true; do
            choix=""
            lire "    $BLEU└─$C0 votre choix ${ESTOMPE}[1]${C0} ${GRAS}›${C0} " choix
            [[ -z "$choix" ]] && choix=1
            case "${choix,,}" in
                a) libre=1; break ;;                         # bascule en saisie libre
                p) printf '    %sétape passée%s\n' "$ESTOMPE" "$C0"; return 1 ;;
                q) printf '\n'; info "arrêt demandé."; journal "ARRÊT demandé à la question [[$nom]]"; exit 0 ;;
                *)
                    if [[ "$choix" =~ ^[0-9]+$ ]] && (( choix >= 1 && choix <= n )); then
                        # La valeur vient d'un programme, pas de votre clavier :
                        # une apostrophe dans un nom de fichier casserait la
                        # commande, on la neutralise comme pour les {{listes}}.
                        VALEUR="$(echapper_apostrophes "${v[$(( choix - 1 ))]}")"
                        printf '    %s→ %s%s\n\n' "$VERT" "${v[$(( choix - 1 ))]}" "$C0"
                        return 0
                    fi
                    printf '    %s« %s » n'"'"'est pas dans la liste%s\n' "$JAUNE" "$choix" "$C0" ;;
            esac
        done
    fi

    # Saisie libre. En mode -y, il n'y a personne pour répondre : mieux
    # vaut s'arrêter net que lancer une commande amputée.
    if [[ "$SANS_QUESTION" == "true" ]]; then
        erreur "[[$nom]] n'a pas de valeur et -y interdit de la demander."
        erreur "Fournissez-la : --var $nom=..."
        exit 1
    fi

    if (( n == 0 )); then
        printf '\n    %s┌─%s %s[[%s]]%s%s%s\n' "$BLEU" "$C0" "$GRAS$CYAN" "$nom" "$C0" \
               "$ESTOMPE" "${ou:+  — sert aux étapes $ou}"
        printf '    %s│%s  %sla valeur sera réutilisée dans toutes les étapes qui la demandent%s\n' \
               "$BLEU" "$C0" "$ESTOMPE" "$C0"
        printf '    %s│%s  %s p%s  %spasser cette étape%s   %s q%s  %squitter%s\n' \
               "$BLEU" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0" "$GRAS" "$C0" "$ESTOMPE" "$C0"
    fi

    # Après un « a » explicite, p et q ne sont plus des raccourcis : vous
    # avez demandé à taper une valeur, c'est donc une valeur — sans quoi
    # une partition nommée « p » serait impossible à saisir.
    VALEUR=""
    while true; do
        lire "    $BLEU└─$C0 valeur ${GRAS}›${C0} " VALEUR
        if (( ! libre )); then
            case "${VALEUR,,}" in
                p) printf '    %sétape passée%s\n' "$ESTOMPE" "$C0"; return 1 ;;
                q) printf '\n'; info "arrêt demandé."; journal "ARRÊT demandé à la question [[$nom]]"; exit 0 ;;
            esac
        fi
        valeur_valide "$VALEUR" && break
    done
    printf '\n'
    return 0
}

# oublier_valeurs <commande brute>
# Efface les [[valeurs]] que CETTE étape utilise — y compris celles qui
# ne sont pas dans la commande mais dans les listes qu'elle appelle — et
# vide le cache des listes, qui en dépendaient. Effacer toutes les
# réponses obligerait à ressaisir ce qui était juste.
oublier_valeurs() {
    local cmd="$1" nom vus=" " i=0 courant
    local -a afaire=("$cmd")

    while (( i < ${#afaire[@]} )); do
        courant="${afaire[$i]}"; i=$(( i + 1 ))
        while [[ "$courant" =~ $RE_SIMPLE ]]; do
            nom="${BASH_REMATCH[1]}"
            unset "REPONSES[$nom]"
            courant="${courant//\[\[$nom\]\]/}"
        done
        while [[ "$courant" =~ $RE_LISTE ]]; do
            nom="${BASH_REMATCH[1]}"
            courant="${courant//\{\{$nom\}\}/}"
            nom="$(liste_de "$nom")"
            if [[ "$vus" != *" $nom "* && -n "${GENERATEUR[$nom]:-}" ]]; then
                vus+="$nom "
                afaire+=("${GENERATEUR[$nom]}")
            fi
        done
    done

    CACHE_LISTE=()
    return 0
}

# resoudre_simples <commande> : remplace les [[valeurs]], résultat dans $CMD.
#   0  commande complète
#   1  l'utilisateur a demandé à passer l'étape
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
            demander_valeur "$nom" || return 1
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
    BINDINGS=()
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

        # C'est la valeur ÉCHAPPÉE qui part dans la commande ; l'étiquette,
        # elle, garde la valeur brute, où un '\'' serait illisible.
        BINDINGS["$cible"]="$(echapper_apostrophes "$val")"
        BINDINGS["${cible}_libelle"]="$(echapper_apostrophes "${lib:-$val}")"

        etiq="$cible=${lib:-$val}"
        _expanser "$cmd" "${label:+$label · }$etiq" $(( prof + 1 ))
        rc=$?

        unset "BINDINGS[$cible]" "BINDINGS[${cible}_libelle]"

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


# --- Affichage d'une étape -------------------------------------------
# etat = cours (en train de se faire), skip (sautée d'office)
titre_etape() {
    local num="$1" total="$2" titre="$3" etat="${4:-cours}"
    printf '\n'
    regle
    printf '  %s %s%s%d/%d%s  %s  %s%s%s\n' \
           "$(glyphe "$etat")" \
           "$GRAS" "$CYAN" "$num" "$total" "$C0" \
           "$(barre "$(( num - 1 ))" "$total")" \
           "$GRAS" "$titre" "$C0"
    regle
}

# afficher_commande <commande> [indentation]
# Repliée aux espaces quand elle dépasse la largeur du terminal : une
# commande de trois cents caractères tassée sur un écran de quatre-vingts
# colonnes est illisible, et c'est précisément celle qu'il faut relire
# avant de la valider.
afficher_commande() {
    local cmd="$1" ind="${2:-  }"
    local dispo=$(( LARGEUR - ${#ind} - 2 ))
    (( dispo < 24 )) && dispo=24

    if (( ${#cmd} <= dispo )); then
        printf '%s%s$%s %s\n' "$ind" "$CYAN" "$C0" "$cmd"
        return 0
    fi

    local premiere=1 ligne
    while IFS= read -r ligne; do
        if (( premiere )); then
            printf '%s%s$%s %s\n' "$ind" "$CYAN" "$C0" "$ligne"
            premiere=0
        else
            printf '%s    %s\n' "$ind" "$ligne"
        fi
    done < <(printf '%s\n' "$cmd" | fold -s -w "$dispo")
}

# resume_iterations : combien d'itérations, et lesquelles
resume_iterations() {
    local n=${#EXP_CMDS[@]} i max=6
    printf '  %s↻%s  %sétape répétée%s — %s%d itération%s%s\n' \
           "$MAGENTA" "$C0" "$MAGENTA" "$C0" "$GRAS" "$n" "$(pluriel "$n")" "$C0"
    for (( i = 0; i < n && i < max; i++ )); do
        printf '     %s%2d%s  %s%s%s\n' "$ESTOMPE" $(( i + 1 )) "$C0" "$ESTOMPE" "${EXP_LABELS[$i]}" "$C0"
    done
    (( n > max )) && printf '     %s..  et %d autre%s — « l » pour tout voir%s\n' \
                            "$ESTOMPE" $(( n - max )) "$(pluriel $(( n - max )))" "$C0"
    (( EXP_TRONQUE )) && attention "limite de $MAX_ITERATIONS itérations atteinte : la liste est tronquée (MAX_ITERATIONS, section 1)"
    return 0
}

lister_iterations() {
    local i
    printf '\n'
    for i in "${!EXP_CMDS[@]}"; do
        printf '     %s%3d%s  %s%s%s\n' "$GRAS" $(( i + 1 )) "$C0" "$MAGENTA" "${EXP_LABELS[$i]}" "$C0"
        afficher_commande "${EXP_CMDS[$i]}" "          "
    done
    printf '\n'
    return 0
}

# menu <clé=texte> ... : la ligne d'options, sous une forme constante.
# La première clé est celle que donne la touche Entrée.
menu() {
    local e ligne="" k t
    for e in "$@"; do
        k="${e%%=*}"; t="${e#*=}"
        ligne+="${ligne:+$ESTOMPE · $C0}${GRAS}${k}${C0} ${ESTOMPE}${t}${C0}"
    done
    printf '  %s\n' "$ligne"
    return 0
}

invite() { printf '  %s›%s ' "$GRAS" "$C0"; }


# --- Exécution d'un groupe d'itérations ------------------------------
# Une étape simple est un groupe d'une itération : un seul chemin de
# code, donc un seul endroit où se tromper.
G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_DUREE=0; G_RC=0
ITERS=()        # "état|détail|étiquette" par itération, pour l'arborescence
executer_groupe() {
    local une_par_une="$1" repetee="$2"
    local n=${#EXP_CMDS[@]} i rc choix ignorer=0 debut=$SECONDS

    G_OK=0; G_KO=0; G_SKIP=0; G_INT=0; G_ARRET=0; G_RC=0
    ITERS=()

    for i in "${!EXP_CMDS[@]}"; do
        if (( repetee )); then
            printf '\n  %s──%s %s%d/%d%s %s──%s %s%s%s\n' \
                   "$ESTOMPE" "$C0" "$GRAS" $(( i + 1 )) "$n" "$C0" \
                   "$ESTOMPE" "$C0" "$MAGENTA" "${EXP_LABELS[$i]}" "$C0"
            afficher_commande "${EXP_CMDS[$i]}" "     "
        fi

        if (( une_par_une )); then
            choix=""
            menu "Entrée=exécuter" "p=passer" "t=tout enchaîner" "q=arrêter la boucle"
            lire "$(invite)" choix
            case "${choix,,}" in
                p) printf '     %s⊘  passée%s\n' "$ESTOMPE" "$C0"
                   G_SKIP=$(( G_SKIP + 1 )); ITERS+=("skip|passee|${EXP_LABELS[$i]}"); continue ;;
                q) printf '     %sboucle arrêtée%s\n' "$JAUNE" "$C0"; G_ARRET=1; break ;;
                t) une_par_une=0 ;;
            esac
        fi

        executer_une "${EXP_CMDS[$i]}" "$F_LOG"
        rc=$?

        if (( INTERROMPU )); then
            INTERROMPU=0
            printf '  %s⊗  interrompu au bout de %s%s\n' "$JAUNE" "$(duree "$DUREE_S")" "$C0"
            G_INT=$(( G_INT + 1 )); ITERS+=("int|$(duree "$DUREE_S")|${EXP_LABELS[$i]}")
            if (( repetee )); then
                demander_oui_non "  Continuer la boucle ? ${ESTOMPE}[O/n]${C0} " || { G_ARRET=1; break; }
                continue
            fi
            break
        fi

        if (( rc == 0 )); then
            if [[ "$SIMULATION" == "true" ]]; then
                printf '  %s◌  simulée%s\n' "$BLEU" "$C0"
                ITERS+=("sim|simulee|${EXP_LABELS[$i]}")
            else
                printf '  %s●  terminée en %s%s\n' "$VERT" "$(duree "$DUREE_S")" "$C0"
                ITERS+=("ok|$(duree "$DUREE_S")|${EXP_LABELS[$i]}")
            fi
            G_OK=$(( G_OK + 1 ))
            continue
        fi

        printf '  %s✗  échec — code %d, %s%s\n' "$ROUGE" "$rc" "$(duree "$DUREE_S")" "$C0"
        G_KO=$(( G_KO + 1 )); G_RC=$rc
        ITERS+=("ko|code $rc|${EXP_LABELS[$i]}")

        if (( F_CONTINU )); then
            printf '  %s(étape marquée « continu » : on poursuit)%s\n' "$ESTOMPE" "$C0"
            continue
        fi
        if (( F_STOP )); then
            erreur "étape marquée « stop » : arrêt du script."
            G_ARRET=2; break
        fi
        (( ignorer )) && continue

        if (( repetee )); then
            choix=""
            menu "Entrée=continuer" "t=continuer sans redemander" "n=arrêter la boucle" "q=quitter"
            lire "$(invite)" choix
            case "${choix,,}" in
                t)   ignorer=1 ;;
                n)   G_ARRET=1; break ;;
                q)   G_ARRET=2; break ;;
            esac
        else
            demander_oui_non "  Continuer quand même ? ${ESTOMPE}[O/n]${C0} " || G_ARRET=2
        fi
    done

    G_DUREE=$(( SECONDS - debut ))
    return 0
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

TOTAL=${#COMMANDES[@]}
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
    plan_initial oui
    printf '\n'
    exit 0
fi

# Contrôles qui n'ont de sens que si l'on va vraiment exécuter.
if [[ "$DEMO" != "true" ]]; then
    [[ -e "$IMAGE" ]] || { erreur "image absente : $IMAGE"; exit 1; }
    [[ -r "$IMAGE" ]] || { erreur "image illisible (droits ?) : $IMAGE"; exit 1; }
fi

# Un fuseau mal orthographié ne se voit qu'à la relecture de la timeline,
# des heures plus tard : autant le dire tout de suite.
if [[ -d /usr/share/zoneinfo && ! -e "/usr/share/zoneinfo/$TZ_MACTIME" ]]; then
    attention "fuseau inconnu du système : $TZ_MACTIME (mactime risque de refuser)"
fi

# Pas de terminal (script lancé depuis cron, ou entrée redirigée) alors
# que des étapes attendent une confirmation : les réponses seront lues sur
# l'entrée standard, et le script s'arrêtera dès qu'elle sera épuisée.
if [[ "$INTERACTIF" == "non" && "$SANS_QUESTION" != "true" ]]; then
    attention "aucun terminal : les réponses seront lues sur l'entrée standard (-y pour ne rien demander)"
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


# --- Bandeau de démarrage --------------------------------------------
printf '\n'
regle "$GRAS"
printf ' %sforensic.sh%s  %s%s · %s · %s%s\n' "$GRAS" "$C0" "$CYAN" "$PC" "$SALLE" "$OS" "$C0"
regle "$GRAS"
if [[ "$DEMO" == "true" ]]; then
    entete "demo"      "$DEMO_RACINE  (bac à sable)"
else
    entete "image"     "$IMAGE"
fi
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

if [[ "$DEMO" == "true" ]]; then
    printf '\n'
    printf '  %sMode démonstration.%s Rien de ce qui suit ne touche à vos données :\n' "$GRAS$MAGENTA" "$C0"
    printf '  %stout se passe dans %s.%s\n\n' "$ESTOMPE" "$DEMO_RACINE" "$C0"
    printf '  %sÀ essayer, dans l'"'"'ordre :%s\n' "$GRAS" "$C0"
    printf '  %s· étape 2 : répondez au menu, puis regardez l'"'"'étape 3 ne plus rien demander%s\n' "$ESTOMPE" "$C0"
    printf '  %s· étape 4 : « l » pour lister les itérations, « u » pour les dérouler une par une%s\n' "$ESTOMPE" "$C0"
    printf '  %s· étape 5 : deux listes emboîtées, alors qu'"'"'une seule est écrite%s\n' "$ESTOMPE" "$C0"
    printf '  %s· n'"'"'importe où : « e » pour éditer, « r » pour ressaisir, Ctrl-C pour arrêter%s\n' "$ESTOMPE" "$C0"
    printf '  %sLe tableau de ces étapes est en section 2 bis du script, commenté ligne à ligne.%s\n' "$ESTOMPE" "$C0"
fi


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
    journal "code $rc en $(duree "$DUREE_S")"
    return "$rc"
}


# --- Boucle principale -----------------------------------------------
NUM=0
NB_FILTREES=0

plan_initial

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
        RECAP+=("$NUM|skip|reprise|$TITRE")
        NB_PASSEES=$(( NB_PASSEES + 1 ))
        continue
    fi

    titre_etape "$NUM" "$TOTAL" "$TITRE"

    INTERROMPU=0
    if ! resoudre_simples "$BRUTE"; then     # l'utilisateur a répondu « p »
        RECAP+=("$NUM|skip|passee|$TITRE")
        NB_PASSEES=$(( NB_PASSEES + 1 ))
        journal "PASSÉE (valeur non fournie) : $TITRE"
        continue
    fi
    CMDBASE="$CMD"                # recopié tout de suite : expanser écrase CMD
    BESOIN_EXP=1

    # Boucle interne : on y revient après une édition, on en sort après
    # une exécution ou un saut.
    while true; do

        if (( BESOIN_EXP )); then
            expanser "$CMDBASE"; RCEXP=$?
            BESOIN_EXP=0

            if (( INTERROMPU )); then
                INTERROMPU=0
                attention "lecture des listes interrompue — étape abandonnée"
                RECAP+=("$NUM|int|listes|$TITRE")
                NB_PASSEES=$(( NB_PASSEES + 1 ))
                break
            fi

            if (( RCEXP != 0 )) || (( ${#EXP_CMDS[@]} == 0 )); then
                erreur "les listes de cette étape n'ont rien donné : rien à exécuter."
                info "vérifiez la commande de liste avec --vars, ou figez-la avec --liste"
                RECAP+=("$NUM|ko|liste vide|$TITRE")
                NB_KO=$(( NB_KO + 1 ))
                if [[ "$SANS_QUESTION" != "true" ]]; then
                    menu "Entrée=passer à la suite" "r=ressaisir les valeurs" "q=quitter"
                    CHOIX=""
                    lire "$(invite)" CHOIX
                    case "${CHOIX,,}" in
                        r) oublier_valeurs "$BRUTE"
                           if resoudre_simples "$BRUTE"; then
                               CMDBASE="$CMD"; BESOIN_EXP=1
                               # l'échec précédent ne compte plus : on réessaie
                               unset 'RECAP[-1]'; NB_KO=$(( NB_KO - 1 ))
                               continue
                           fi ;;
                        q) printf '\n'; info "arrêt demandé."; exit 1 ;;
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
        (( F_LOG ))     && info "la sortie de cette étape est recopiée dans le journal"
        (( F_STOP ))    && info "un échec ici arrête le script"
        (( F_CONTINU )) && info "un échec ici est ignoré, sans question"

        # Un CHOIX vide vaut « exécuter » : c'est ce qui rend les étapes
        # validation=false automatiques, sans rien demander.
        CHOIX=""
        if [[ "$F_VALIDER" == "true" || "$TOUT_VALIDER" == "true" ]]; then
            if (( REPETEE )); then
                menu "Entrée=tout exécuter" "u=une par une" "l=lister" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"
            else
                menu "Entrée=exécuter" "p=passer" "e=éditer" "r=ressaisir" "q=quitter"
            fi
            lire "$(invite)" CHOIX
        fi

        case "${CHOIX,,}" in
            ""|o|y|u|t)
                UNE_PAR_UNE=0
                [[ "${CHOIX,,}" == "u" ]] && UNE_PAR_UNE=1
                executer_groupe "$UNE_PAR_UNE" "$REPETEE"
                if (( REPETEE )) && (( ${#ITERS[@]} > 0 )); then
                    ENFANTS["$NUM"]="$(printf '%s\x01' "${ITERS[@]}")"
                fi

                if (( REPETEE )); then
                    # Bilan agrégé : une ligne de récapitulatif par étape,
                    # même si elle a tourné trois cents fois.
                    if [[ "$SIMULATION" == "true" ]]; then
                        RECAP+=("$NUM|sim|$N iter|$TITRE")
                    elif (( G_KO == 0 && G_INT == 0 && G_SKIP == 0 )); then
                        RECAP+=("$NUM|ok|$G_OK/$N$( (( EXP_TRONQUE )) && printf ' tronq') $(duree "$G_DUREE")|$TITRE")
                        NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"
                    elif (( G_KO > 0 )); then
                        RECAP+=("$NUM|ko|$G_KO KO /$N|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                    else
                        RECAP+=("$NUM|int|$G_OK/$N ok|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 ))
                        (( G_INT )) && RECAP[-1]="$NUM|int|$G_OK/$N, $G_INT int|$TITRE"
                    fi
                    printf '\n  %s└─%s  %s%d réussie%s%s · %s%d échec%s%s · %s%d interrompue%s%s · %s%d passée%s%s · %s%s%s\n' \
                           "$ESTOMPE" "$C0" \
                           "$VERT"    "$G_OK"   "$(pluriel "$G_OK")"   "$C0" \
                           "$ROUGE"   "$G_KO"   "$(pluriel "$G_KO")"   "$C0" \
                           "$JAUNE"   "$G_INT"  "$(pluriel "$G_INT")"  "$C0" \
                           "$ESTOMPE" "$G_SKIP" "$(pluriel "$G_SKIP")" "$C0" \
                           "$ESTOMPE" "$(duree "$G_DUREE")" "$C0"
                else
                    if (( G_INT )); then
                        RECAP+=("$NUM|int|$(duree "$G_DUREE")|$TITRE"); NB_PASSEES=$(( NB_PASSEES + 1 ))
                        if (( ! G_ARRET )); then
                            demander_oui_non "  Passer à l'étape suivante ? ${ESTOMPE}[O/n]${C0} " \
                                || { printf '\n'; info "arrêt demandé."; exit 130; }
                        fi
                    elif (( G_KO )); then
                        RECAP+=("$NUM|ko|code $G_RC|$TITRE"); NB_KO=$(( NB_KO + 1 ))
                    elif [[ "$SIMULATION" == "true" ]]; then
                        RECAP+=("$NUM|sim|simulee|$TITRE")
                    else
                        RECAP+=("$NUM|ok|$(duree "$G_DUREE")|$TITRE")
                        NB_OK=$(( NB_OK + 1 )); marquer_faite "$CLE"
                    fi
                fi

                (( G_ARRET == 2 )) && { printf '\n'; info "arrêt."; exit 1; }
                break
                ;;

            l)
                lister_iterations
                ;;

            p)
                printf '  %s⊘  passée%s\n' "$ESTOMPE" "$C0"
                RECAP+=("$NUM|skip|passee|$TITRE")
                NB_PASSEES=$(( NB_PASSEES + 1 ))
                journal "PASSÉE : $TITRE"
                break
                ;;

            e)
                # Modification ponctuelle, non enregistrée dans le tableau.
                # On repasse par la résolution au cas où l'édition ajoute
                # un [[nom]] ou un {{nom}}.
                info "édition — la modification ne vaut que pour cette exécution"
                NOUVELLE=""
                lire_edit "$CMDBASE" NOUVELLE
                if [[ -z "${NOUVELLE// /}" ]]; then
                    attention "commande vide : édition annulée"
                else
                    if resoudre_simples "$NOUVELLE"; then
                        CMDBASE="$CMD"
                        BESOIN_EXP=1
                    else
                        attention "édition annulée"
                    fi
                fi
                ;;

            r)
                # Un chiffre oublié dans l'offset ? On repart des questions,
                # mais seulement pour les valeurs de CETTE étape : effacer
                # tout obligerait à ressaisir ce qui était juste.
                oublier_valeurs "$BRUTE"
                if resoudre_simples "$BRUTE"; then
                    CMDBASE="$CMD"
                    BESOIN_EXP=1
                    info "valeurs ressaisies"
                else
                    RECAP+=("$NUM|skip|passee|$TITRE")
                    NB_PASSEES=$(( NB_PASSEES + 1 ))
                    break
                fi
                ;;

            q)
                printf '\n'; info "arrêt demandé."
                exit 0
                ;;

            *)
                printf '  %s« %s » n'"'"'est pas une réponse attendue%s\n' "$JAUNE" "$CHOIX" "$C0"
                ;;
        esac
    done
done

(( NB_FILTREES > 0 )) && info "$NB_FILTREES étape(s) écartée(s) par --seulement / --depuis"

# Le code de sortie sert à enchaîner : 0 si tout est passé, 1 s'il reste
# une étape en échec — même si vous avez choisi de continuer sur le coup.
(( NB_KO > 0 )) && exit 1
exit 0
