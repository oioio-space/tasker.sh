#!/usr/bin/env bash
# Le plan de collecte-linux.conf, famille par famille, sur un faux montage :
# la bonne branche de paquets est-elle choisie, la conf se lit-elle ?
#
#     tests/plan.sh [dossier de travail]
#
# Ne collecte rien : « -l » affiche le plan, c'est tout. Vérifie que la
# syntaxe passe et que chaque famille choisit son gestionnaire de paquets.
set -u
ici="$(cd "$(dirname "$0")/../../.." && pwd)"
travail="${1:-$(mktemp -d)}"
conf="$ici/exemples/collecte-linux.conf"
bash -n "$conf" || exit 1

declare -A attendu=(
    [debian]="dpkg-query"  [fedora]="rpm --dbpath"  [opensuse]="rpm --dbpath"
    [arch]="pacman_local"  [alpine]="apk_installed"
)
declare -A marqueur=(
    [debian]="var/lib/dpkg/status"   [fedora]="var/lib/rpm/x"  [opensuse]="var/lib/rpm/x"
    [arch]="var/lib/pacman/local/x-1/desc"  [alpine]="lib/apk/db/installed"
)
motifs_attendus=(urls courriels ip mac chemins)
rc=0
dernier=""
for f in debian fedora opensuse arch alpine; do
    m="$travail/faux-$f"
    rm -rf "$m"; mkdir -p "$m/etc" "$m/$(dirname "${marqueur[$f]}")" "$m/home/toto"
    echo "ID=$f" > "$m/etc/os-release"; echo pc > "$m/etc/hostname"
    printf 'root:x:0:0::/root:/bin/sh\ntoto:x:1000:1000::/home/toto:/bin/sh\n' > "$m/etc/passwd"
    : > "$m/${marqueur[$f]}"
    plan="$("$ici/tasker.sh" -c "$conf" -l --set MONTAGE="$m" --set PERIPH=/dev/loop0 \
            --set PC=PC01 --set SALLE=T --set PROJET=T --set OS=LINUX --set ANALYSE="$travail/analyse" 2>&1)"
    if grep -q -- "${attendu[$f]}" <<< "$plan"; then
        printf '  %-9s ok  (%s)\n' "$f" "${attendu[$f]}"
    else
        printf '  %-9s KO  — « %s » absent du plan\n' "$f" "${attendu[$f]}"; rc=1
    fi
    [[ "$f" == debian ]] && dernier="$plan"
done

# Deux points que le plan seul suffit à trancher, et qui coûtaient très cher.
# tasker.sh replie les commandes longues : on remet le plan sur une ligne
# avant de chercher.
plat="$(tr '\n' ' ' <<< "$dernier" | tr -s ' ')"

# « strings » nu ne rend que de l'ASCII 7 bits et TRANCHE au premier octet
# accentué. Mesuré sur un disque français :
#   /home/jean/Téléchargements/note.txt  →  « /home/jean/T »
#   jean.dupé@example.com                →  « @example.com »   (plus personne)
#   https://café.example.com/page        →  « https://caf »
# « -e S » lit un octet sur huit bits : les trois ressortent entières.
if grep -q -- "strings -e S '{{volume}}'" <<< "$plat"; then
    printf '  %-9s ok  (les accents passent)\n' "chaînes"
else
    printf '  %-9s KO  — « strings -e S » absent : les chaînes accentuées seront tronquées\n' "chaînes"
    rc=1
fi

# Chaque fichier brut est posé VIDE avant awk, qui n'y écrit qu'en cas de
# correspondance. Sans cela un genre sans trouvaille laissait « sort » sans
# fichier ; sous « set -o pipefail », que tasker.sh pose, la chaîne de &&
# s'arrêtait là et TOUS les genres suivants étaient perdus, l'étape passant au
# rouge. Mesuré sur un disque sans une seule adresse de courriel : « ip »,
# « mac » et « chemins » jamais produits. Un disque sans courriel est normal.
poses=$(grep -o ' : > ' <<< "$plat" | wc -l)
if (( poses == ${#motifs_attendus[@]} )); then
    printf '  %-9s ok  (%d genres, aucun ne peut emporter les suivants)\n' "extraits" "$poses"
else
    printf '  %-9s KO  — %d fichiers bruts posés pour %d genres\n' \
           "extraits" "$poses" "${#motifs_attendus[@]}"
    rc=1
fi
exit $rc
