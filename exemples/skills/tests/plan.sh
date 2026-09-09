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
rc=0
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
done
exit $rc
