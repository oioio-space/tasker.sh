# Une pièce manque : où la reprendre

L'extraction signale chaque pièce absente comme un fait de catégorie `limite`,
avec son **chemin d'origine** et l'**étape** de `collecte-linux.conf` à rejouer.
Cette fiche dit ce qu'il faut en faire.

**Cherchez d'abord la pièce qui manque** :
`grep -n 'lastlog' references/ou-chercher.md`.

| section | ce qu'elle donne |
|---|---|
| `## D'abord : distinguer deux absences` | les absences NORMALES, système par système |
| `## Comment savoir laquelle` | le rapport de collecte, et où il se trouve |
| `## Aller la lire vous-même sur l'image` | ce que vous pouvez faire seul, tout de suite |
| `## Reprendre une pièce` | rejouer une étape de collecte |
| `## Où poser une pièce reprise à la main` | le nom que l'extracteur attend |
| `## Où chaque pièce vit sur le système` | le chemin d'origine de chacune |
| `## Ce qu'aucune remontée ne rendra` | ce qu'il faut renoncer à chercher |

## D'abord : distinguer deux absences

Elles n'ont pas la même conséquence, et le rapport ne doit pas les confondre.

**Le système ne l'avait pas.** C'est un fait *sur ce système*, à écrire comme
tel. Exemples :

| pièce absente | ce que ça dit |
|---|---|
| `/var/log/secure`, `auth.log` | Fedora et dérivés récents n'installent pas rsyslog : tout est dans le journal systemd |
| `/var/log/wtmp` | Fedora 40+, Debian 13+ : remplacé par `/var/lib/wtmpdb/wtmp.db` ; Alpine (musl) : n'existe pas du tout |
| `/var/log/lastlog` | idem : remplacé par `/var/lib/lastlog/lastlog2.db` |
| `/var/log/btmp` | souvent absent ou désactivé — n'en concluez **aucune** absence d'attaque |
| `/etc/sssd`, `krb5.conf` | la machine n'était pas dans un domaine |
| `/etc/adjtime` | fréquent ; ne dit rien de l'horloge |
| `/var/log/journal` | journal en mémoire seulement (`Storage=volatile`) : **tout est perdu à l'extinction** ; Alpine, Devuan : pas de systemd, tout est dans `/var/log/messages` |
| `rpm -qa --last` vide | openSUSE : base RPM au format `ndb`, que le `rpm` du poste d'analyse ne lit pas toujours — les poses sont dans `/var/log/zypp/history` |
| `~/.bash_history` sur un compte qui a servi | effaçable par son propriétaire : c'est un fait notable |

**La collecte l'a ratée.** Il faut y retourner. Les causes courantes :

- l'étape a été **passée** à la main (touche `p`) — les étapes lourdes,
  `photorec` et « Caches et profils », le sont souvent en triage ;
- l'étape est **rouge** dans le journal de la collecte ;
- un outil manquait sur le poste d'analyse (`journalctl`, `sqlite3`, `fls`…) ;
- un volume n'était pas monté au moment de la collecte — un `/home` sur un
  autre volume, typiquement.

## Comment savoir laquelle

Demandez le **rapport de la collecte** : `PREFIX_rapport.txt`, et le journal
`PREFIX_script.log`. Ils donnent, étape par étape, ce qui a réussi, échoué ou
été passé — c'est la réponse directe.

**Attention** : ils ne sont **pas** dans le dossier de collecte. Ils sont là où
`tasker.sh` a été lancé, dans un sous-dossier au nom du PREFIX. Si vous ne les
avez pas, demandez-les : sans eux, on ne peut pas distinguer « le système ne
l'avait pas » de « la collecte a échoué », et il faut le dire dans le rapport
plutôt que de choisir.

## Aller la lire vous-même sur l'image

C'est le geste le plus rapide, et il ne demande personne. **Si l'image est
montée à côté de la collecte, allez-y.** Par convention elle est sous `mnt/`
dans le dossier d'analyse ; si l'analyste vous indique un autre point de
montage, c'est celui-là qui vaut. Un `ls` sur le dossier d'analyse vous le
montre ; une racine Linux se reconnaît à ce qu'elle porte `etc/` et `usr/`.

**Tout ce qui LIT y est permis**, par les outils comme par `bash` :

    ls mnt/var/log/
    cat mnt/etc/os-release
    stat mnt/var/log/wtmp
    strings mnt/var/log/journal/*/system.journal | grep -i ssh
    find mnt/home -name 'places.sqlite'
    sqlite3 'file:mnt/home/jdupont/.mozilla/…/places.sqlite?mode=ro' '.tables'
    tar -tzf mnt/var/backups/x.tar.gz

**Rien n'y est écrit, jamais.** L'image est montée en lecture seule, et la
garde des scellés refuse en plus toute écriture — une redirection dont la cible
est dedans, un `cp` ou un `rm` qui la vise, un `sed -i`. Ce n'est pas une
contrariété à contourner : une image qu'on a modifiée n'est plus une preuve.
Dirigez toute sortie vers le dossier d'analyse :

    strings mnt/var/log/wtmp > analyse/wtmp-chaines.txt      ← oui
    strings mnt/var/log/wtmp > mnt/tmp/wtmp-chaines.txt      ← refusé

**Dites d'où vient ce que vous en tirez.** Une pièce lue sur l'image n'a
traversé ni la collecte ni le manifeste : elle n'a donc **pas d'empreinte**, et
rien ne prouvera plus tard que vous avez lu ce que vous dites avoir lu. Deux
conséquences, toutes deux à respecter :

- dans le rapport, citez la source comme *l'image montée*, jamais comme la
  collecte — « `mnt/etc/hostname` (image montée, hors collecte) » ;
- quand la pièce compte pour une conclusion, ne vous arrêtez pas là :
  **recopiez-la dans la collecte** sous le nom attendu (section suivante) et
  relancez l'extraction, ou demandez la reprise de l'étape. Elle entre alors au
  manifeste avec son empreinte, et le rapport redevient reproductible.

Le tableau `## Où chaque pièce vit sur le système`, plus bas, donne le chemin
d'origine de chaque pièce : c'est celui-là qu'il faut préfixer par le point de
montage.

## Reprendre une pièce

Si l'image est encore montée :

    sudo ./tasker.sh -c exemples/collecte-linux.conf --only <numéros> \
         --set MONTAGE=/mnt/investigation --set PERIPH=/dev/…

`--only` ne rejoue que les étapes nommées. Les numéros se lisent dans le plan :

    sudo ./tasker.sh -c exemples/collecte-linux.conf -l --set MONTAGE=… --set PERIPH=…

Si l'image n'est plus montée, elle doit l'être **en lecture seule** :

    sudo losetup -r -f --show -P image.dd
    sudo mount -o ro,noatime /dev/loopXpN /mnt/investigation

Sur un XFS dont le journal est sale, ajoutez `norecovery`. Sur un LVM, activez
d'abord les volumes (`vgchange -ay`). Et si l'image porte plusieurs volumes —
un `/home` séparé —, **montez-les tous** sous le point de montage avant de
rejouer : la collecte les traite alors comme la racine.

## Où poser une pièce reprise à la main

Si vous ne rejouez pas l'étape mais recopiez le fichier depuis l'image, posez-le
dans le dossier de la collecte **sous le nom que l'extracteur attend**, puis
relancez l'extraction. Il sera lu comme si la collecte l'avait emporté, et le
manifeste en portera l'empreinte.

| pièce | où la poser | nom attendu |
|---|---|---|
| un journal texte (`auth.log`, `secure`, `messages.3.gz`) | `JOURNAUX/` | tel quel — tout fichier de `JOURNAUX/` qui n'est ni l'archive ni `_journal.txt` est lu comme un journal, décompressé s'il le faut |
| `wtmp`, `wtmp.1`, `btmp` | `CONNEXIONS/` | tel quel — le nom doit commencer par `wtmp` ou `btmp` |
| `lastlog` | `CONNEXIONS/` | `lastlog` |
| `wtmp.db`, `lastlog2.db` | `CONNEXIONS/` | tel quel |
| `passwd` | `COMPTES/` | `PREFIX_passwd.txt` |
| les fichiers d'un compte | `COMPTES/` | une archive `PREFIX_<compte>_artefacts.tar.gz` ou `_profils.tar.gz` — `tar -czf … -C /mnt/investigation/home/<compte> .mozilla .config …` |
| le journal systemd | `JOURNAUX/` | `PREFIX_journal.txt`, sortie de `journalctl -D var/log/journal -o short-iso` |

Le PREFIX est celui du dossier. Une pièce mal nommée n'est pas lue, et rien ne
le dira : vérifiez qu'elle apparaît dans `faits-manifeste.json`.

## Où chaque pièce vit sur le système

Ce que l'étape de collecte va chercher, pour aller la prendre à la main si
besoin.

| ce qui manque | chemin d'origine |
|---|---|
| nom de la machine | `/etc/hostname` |
| distribution | `/etc/os-release` |
| fuseau | `/etc/localtime` (un lien dont la cible nomme le fuseau) |
| identité, installation | `/etc/machine-id`, `/etc/adjtime`, `/etc/machine-info`, `/etc/crypttab`, `/var/lib/systemd/timesync/clock`, `/var/log/anaconda/`, `/var/log/installer/`, `/root/*-ks.cfg` |
| paquets | `/var/lib/rpm` (copier avant de lire) ou `/var/lib/dpkg/status` ; `/var/lib/pacman/local` (Arch) ; `/lib/apk/db/installed` (Alpine) |
| historique des paquets | `/var/log/dpkg.log`, `/var/log/apt/`, `/var/log/yum.log`, `/var/log/dnf*.log`, `/var/lib/dnf/history.sqlite`, `/usr/lib/sysimage/libdnf5/`, `/var/log/zypp/history`, `/var/log/pacman.log`, `/etc/apk/world` |
| comptes | `/etc/passwd`, `/etc/group` |
| droits | `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/pam.d/`, `/etc/security/`, `/etc/login.defs`, `/etc/selinux/config`, `/etc/apparmor.d/` |
| domaine | `/etc/sssd/`, `/etc/krb5.conf`, `/etc/krb5.keytab`, `/etc/samba/`, `/etc/openldap/`, `/var/lib/sss/db/` |
| sessions, échecs | `/var/log/wtmp*`, `/var/log/btmp*`, `/var/log/lastlog`, `/var/lib/wtmpdb/wtmp.db`, `/var/lib/lastlog/lastlog2.db` |
| journal systemd | `/var/log/journal/<machine-id>/*.journal` |
| journaux texte | `/var/log/` en entier |
| réseau | `/etc/NetworkManager/system-connections/`, `/etc/sysconfig/network-scripts/`, `/etc/netplan/`, `/etc/systemd/network/`, `/etc/wpa_supplicant/`, `/var/lib/iwd/`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/ssh/`, `/var/lib/NetworkManager/`, `/var/lib/dhclient/` |
| pare-feu | `/etc/firewalld/`, `/etc/ufw/`, `/etc/iptables/`, `/etc/nftables.conf`, `/etc/sysconfig/iptables` |
| persistance | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`, `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/etc/rc.local`, `/etc/profile.d/`, `/etc/ld.so.preload`, `/etc/udev/rules.d/` |
| traces d'un compte | `~/.bash_history`, `~/.zsh_history`, `~/.viminfo`, `~/.lesshst`, `~/.ssh/` |
| profils applicatifs | `~/.mozilla/`, `~/.config/`, `~/.local/`, `~/.cache/`, `~/snap/`, `~/.var/app/` |
| paquets hors système | `/var/lib/snapd/state.json`, `/var/lib/flatpak/` |
| timeline | le périphérique, ou le montage à défaut |

## Ce qu'aucune remontée ne rendra

Inutile de retourner à l'image pour ça — dites-le dans « Les limites » :

- la **mémoire vive**, si la machine a été éteinte ;
- le **trafic réseau**, jamais capturé ;
- le **numéro de série** de la machine : il faut le BIOS, machine allumée ;
- le contenu d'un **support amovible** qui n'a pas été saisi ;
- ce que la **rotation** des journaux a supprimé ;
- ce qu'un **inode réutilisé** a écrasé.
