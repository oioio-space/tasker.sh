#!/usr/bin/env bash
# Le plan de collecte-linux.conf, famille par famille, sur un faux montage :
# la bonne branche de paquets est-elle choisie, la conf se lit-elle ?
#
#     tests/plan.sh [dossier de travail]
#
# Ne collecte rien : « -l » affiche le plan, c'est tout.
set -u
ici="$(cd "$(dirname "$0")/../../.." && pwd)"
travail="${1:-$(mktemp -d)}"
conf="$ici/exemples/collecte-linux.conf"
bash -n "$conf" || exit 1
rc=0
dire() { # <libellé> <ok|KO> <détail>
    printf '  %-10s %s  %s\n' "$1" "$2" "$3"; [[ "$2" == KO ]] && rc=1; return 0
}

# Une famille = les fichiers qui la désignent, et ce que le plan doit porter.
# La base RPM se reconnaît à son FICHIER, pas à son dossier : rpmdb.sqlite
# (Fedora, RHEL 9), Packages.db (ndb, openSUSE), Packages (bdb, RHEL 7 et 8),
# et depuis Fedora 36 elle a déménagé dans usr/lib/sysimage/rpm. Un dossier
# var/lib/rpm sans aucun de ces fichiers — migration, ou rpm simple outil sur
# une Debian — ne doit PAS faire choisir rpm : c'est là que la collecte
# rendait une liste vide sans une erreur.
declare -A pieces=(
    [debian]="var/lib/dpkg/status"
    [fedora]="usr/lib/sysimage/rpm/rpmdb.sqlite"
    [rhel9]="var/lib/rpm/rpmdb.sqlite"
    [rhel7]="var/lib/rpm/Packages"
    [opensuse]="usr/lib/sysimage/rpm/Packages.db"
    [arch]="var/lib/pacman/local/x-1/desc"
    [alpine]="lib/apk/db/installed"
    [rpm_migre]="var/lib/rpm/.rpm.lock"
    # un dpkg installé en simple OUTIL sur une Fedora : le dossier est là, le
    # status est vide, et dpkg l'emportait sur une base RPM pleine
    [fedora_dpkg]="usr/lib/sysimage/rpm/rpmdb.sqlite var/lib/dpkg/status@vide"
    # un dossier pacman sans un seul paquet
    [pacman_vide]="var/lib/pacman/local/.keep"
)
declare -A attendu=(
    [debian]="dpkg-query"
    [fedora]="rpm --dbpath"   [rhel9]="rpm --dbpath"   [rhel7]="rpm --dbpath"
    [opensuse]="rpm --dbpath"
    [arch]="pacman_local"     [alpine]="apk_installed"
    [rpm_migre]="ni base dpkg"
    [fedora_dpkg]="rpm --dbpath"
    [pacman_vide]="ni base dpkg"
)
plan_de() {   # <montage>
    "$ici/tasker.sh" -c "$conf" -l --set MONTAGE="$1" --set PERIPH=/dev/loop0 \
        --set PC=PC01 --set SALLE=T --set PROJET=T --set OS=LINUX \
        --set ANALYSE="$travail/analyse" 2>&1
}

dernier=""
for f in debian fedora rhel9 rhel7 opensuse arch alpine rpm_migre fedora_dpkg pacman_vide; do
    m="$travail/faux-$f"
    rm -rf "$m"; mkdir -p "$m/etc" "$m/home/toto" "$m/var/log"
    echo "ID=$f" > "$m/etc/os-release"; echo pc > "$m/etc/hostname"
    printf 'root:x:0:0::/root:/bin/sh\ntoto:x:1000:1000::/home/toto:/bin/sh\n' > "$m/etc/passwd"
    # « chemin@vide » pose un fichier VIDE : un dossier de base qui existe sans
    # rien dedans ne doit pas faire choisir son gestionnaire.
    for piece in ${pieces[$f]}; do
        mkdir -p "$m/$(dirname "${piece%@vide}")"
        [[ "$piece" == *@vide ]] && : > "$m/${piece%@vide}" || printf 'x' > "$m/$piece"
    done
    [[ "$f" == debian ]] && echo "Jan  1 00:00:00 pc sshd[1]: Accepted password for toto from 10.0.0.1" > "$m/var/log/auth.log"
    plan="$(plan_de "$m")"
    if grep -q -- "${attendu[$f]}" <<< "$plan"
    then dire "$f" ok  "(${attendu[$f]})"
    else dire "$f" KO  "— « ${attendu[$f]} » absent du plan"
    fi
    # Une base vide ne doit surtout pas passer pour une base RPM
    if [[ "$f" == rpm_migre ]] && grep -q -- "rpm --dbpath" <<< "$plan"; then
        dire "$f" KO "— var/lib/rpm sans base a quand même choisi rpm"
    fi
    [[ "$f" == debian ]] && dernier="$plan"
done

# tasker.sh replie les commandes longues : on remet le plan sur une ligne.
plat="$(tr '\n' ' ' <<< "$dernier" | tr -s ' ')"

# rpm -qa rend une liste VIDE avec un code 0 quand la base ne lui dit rien :
# l'étape doit refuser une liste vide, sinon elle passe au vert sans un paquet.
if grep -q "liste de paquets VIDE" <<< "$plat"
then dire paquets ok "(une liste vide est une erreur)"
else dire paquets KO "— rien ne refuse une liste de paquets vide"
fi

# Succès et échecs d'authentification : wtmp et btmp ne suffisent pas, et sur
# Arch ou Fedora ils n'existent même pas.
if grep -q "auth_succes.txt" <<< "$plat" && grep -q "auth_echecs.txt" <<< "$plat"
then dire auth ok "(succès et échecs relevés dans les journaux)"
else dire auth KO "— les authentifications ne sont pas relevées"
fi

# strings NU : sans une option, et sans rien chercher dans sa sortie. La pièce
# est le texte brut du périphérique, tel que l'outil le rend. Ce qu'on cherche
# dedans se cherche ensuite, sur la pièce (extraire.py --indicateurs).
if grep -q -- "strings '{{volume}}' > " <<< "$plat"
then dire chaînes ok "(strings nu)"
else dire chaînes KO "— « strings '{{volume}}' » absent du plan"
fi
if grep -qE -- "strings '\{\{volume\}\}' -|strings -" <<< "$plat"
then dire chaînes KO "— strings porte une option"
fi
# Aucune recherche sur la sortie de strings : ni awk de motifs, ni extraits.
if grep -qE -- "Extraits des chaînes|\.brut" <<< "$plat"
then dire extraits KO "— une recherche particulière est encore faite sur les chaînes"
else dire extraits ok "(aucune recherche sur la sortie de strings)"
fi

# Arch, et toute image récente dont systemd n'écrit plus utmp, n'a ni wtmp, ni
# btmp, ni lastlog : « cp -aL » se retrouvait SANS SOURCE et l'étape passait au
# rouge sur une collecte saine. Pas de pièce, pas d'étape — mais l'étape doit
# revenir dès qu'il y a un fichier à copier.
sans="$travail/faux-arch"
if grep -q "Copie des fichiers de connexion" <<< "$(plan_de "$sans")"
then dire connexions KO "— cp -aL sans source sur une image sans wtmp"
else
    avec="$travail/faux-connexions"
    rm -rf "$avec"; cp -a "$sans" "$avec"; : > "$avec/var/log/wtmp"
    if grep -q "Copie des fichiers de connexion" <<< "$(plan_de "$avec")"
    then dire connexions ok "(pas de pièce, pas d'étape ; une pièce, une étape)"
    else dire connexions KO "— wtmp présent et pourtant aucune étape de copie"
    fi
fi

# Les comptes sans session ne sont pas relevés. nologin n'est pas le seul :
# openSUSE et Alpine posent /bin/false, Debian /bin/sync, et le chemin de
# nologin change de distribution en distribution.
m="$travail/faux-comptes"
rm -rf "$m"; mkdir -p "$m/etc" "$m/root" "$m/home/toto" "$m/home/svc1" "$m/home/svc2" \
                      "$m/home/svc3" "$m/home/svc4" "$m/home/vide" "$m/bin"
cat > "$m/etc/passwd" <<'PASSWD'
root:x:0:0::/root:/bin/bash
toto:x:1000:1000::/home/toto:/bin/bash
vide:x:1001:1001::/home/vide:
svc1:x:990:990::/home/svc1:/usr/sbin/nologin
svc2:x:991:991::/home/svc2:/sbin/nologin
svc3:x:992:992::/home/svc3:/bin/false
svc4:x:993:993::/home/svc4:/usr/bin/false
sync:x:4:65534::/bin:/bin/sync
nul:x:994:994::/home/toto:/dev/null
PASSWD
retenus="$( MONTAGE="" INTERROMPU=0
            . "$conf" >/dev/null 2>&1
            MONTAGE="$m"; INTERROMPU=0
            emettre() { printf '%s\n' "$2"; }
            lister_comptes 2>/dev/null | sort | tr '\n' ' ' )"
if [[ "$retenus" == "root toto vide " ]]
then dire comptes ok "(retenus : $retenus)"
else dire comptes KO "— attendu « root toto vide », obtenu « $retenus »"
fi
exit $rc
