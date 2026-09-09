# Inventaire : où est chaque trace, et jusqu'où elle va

Pour chaque question qu'on pose à une machine : **la trace**, **la pièce** de la
collecte qui la porte, si l'extraction la lit, et **ce qui manque**.

Une case « — » n'est pas un oubli : c'est une chose qu'aucune pièce ne dit.
Elle a autant de valeur que le reste, et doit se retrouver dans « Les limites »
du rapport.

---

## Identifier la machine

| question | trace | pièce | lu | limite |
|---|---|---|---|---|
| nom | `/etc/hostname` | `SYSTEME/hostname` | oui | nom au moment de la collecte |
| nom dans le domaine | — | — | — | **aucune pièce**. À demander à l'annuaire |
| nom affiché, châssis | `/etc/machine-info` | `SYSTEME/…_installation.tar.gz` | oui | absent sur beaucoup de systèmes |
| modèle et BIOS | ligne `DMI:` du noyau | `JOURNAUX/` (journal, `dmesg`) | oui | le modèle, pas le numéro de série |
| volumes chiffrés | `/etc/crypttab` | `SYSTEME/…_installation.tar.gz` | oui | dit qu'un volume chiffré existait |
| horloge synchronisée | `var/lib/systemd/timesync/clock` | idem | oui, par la **date du fichier** | au-delà, les dates sont moins sûres |
| système, version | `/etc/os-release` | `SYSTEME/os-release` | oui | |
| identité unique | `/etc/machine-id` | `SYSTEME/…_installation.tar.gz` | oui | relie au dossier du journal systemd |
| numéro de série matériel | — | — | — | **aucune pièce** : il faut le BIOS (`dmidecode`), machine allumée |
| date d'installation | journaux anaconda / installer | `SYSTEME/…_installation.tar.gz` | oui, par la **date du membre dans l'archive** | la plus sûre : tar conserve la date, que le contenu ne porte pas |
| date d'installation (Debian, Ubuntu) | 1ʳᵉ ligne de `var/log/dpkg.log` | `PAQUETS/…_historique.tar.gz` | oui | `dpkg-query -l` ne date **rien** : c'est ici que ça se lit |
| date d'installation (à défaut) | plus ancien paquet `rpm -qa --last` | `PAQUETS/…_paquets.txt` | oui | RPM seulement ; fausse si le système a été migré |
| dernier arrêt | `wtmp` | `CONNEXIONS/…_reboots.txt`, `wtmp` | oui | un arrêt brutal n'écrit rien |
| fuseau, horloge RTC | `/etc/localtime`, `/etc/adjtime` | `SYSTEME/` | oui | |

## Qui existe, qui a servi

| question | trace | pièce | lu | limite |
|---|---|---|---|---|
| comptes locaux | `/etc/passwd` | `COMPTES/passwd` | oui | exister ≠ avoir servi |
| comptes du domaine | cache SSSD | `COMPTES/…_domaine.tar.gz` → `var/lib/sss/db` | oui | **indispensable** : `/etc/passwd` ne les a pas |
| sessions ouvertes | `wtmp` **et ses rotations** | texte de `last`, **ou les binaires** | oui | la collecte prend `wtmp`, `wtmp.1` **et** `wtmp-20190901` : les deux styles de rotation, donc des mois d'historique en plus |
| échecs | `btmp` et ses rotations | texte de `lastb`, **ou les binaires** | oui | souvent vide ou désactivé |
| SSH, sudo, su (Debian, Ubuntu) | `var/log/auth.log` | `JOURNAUX/…_var_log.tar.gz` | oui | **la ligne syslog n'a pas d'année** : elle est déduite de la date du fichier, et le fait est marqué « forte », pas « certaine » |
| SSH, sudo, su (RHEL ancien) | `var/log/secure` | idem | oui | même remarque sur l'année |
| SSH, sudo, su (Fedora, RHEL récent) | journal systemd | `JOURNAUX/…_journal.txt` | oui | date complète, avec fuseau |
| dernière connexion | `lastlog`, `lastlog2.db` | `CONNEXIONS/` | oui (binaire 292 o et sqlite) | écrasée à chaque fois |
| sessions (Fedora 40+) | `wtmp.db` sqlite | `CONNEXIONS/wtmp.db` | oui | |
| qui était au clavier | — | — | — | **aucune pièce ne le dit jamais** |

## Le domaine

| question | trace | pièce | lu |
|---|---|---|---|
| domaine, contrôleurs | `sssd.conf` | `COMPTES/…_domaine.tar.gz` | oui |
| royaume, KDC | `krb5.conf` | idem | oui |
| adhésion prouvée | `krb5.keytab` | idem | oui (présence) |
| groupe SMB | `smb.conf` | idem | oui |
| domaine deviné | `resolv.conf` `search` | `RESEAU/…_reseau.tar.gz` | oui |

## Le réseau

| question | trace | pièce | lu | limite |
|---|---|---|---|---|
| MAC | profils NM, `ifcfg-*` | `RESEAU/…_reseau.tar.gz` | oui | la configuration, pas l'état |
| IP fixe | idem | idem | oui | |
| IP obtenue | baux DHCP | idem | oui | **daté** : prouve que la machine était active |
| DNS, passerelle | `resolv.conf`, `ifcfg` | idem | oui | |
| réseaux Wi-Fi | `ssid=` des profils NM | idem | oui | prouve une association, sans date |
| hôtes SSH contactés | `.ssh/known_hosts` | `COMPTES/…_artefacts.tar.gz` | oui | souvent **haché** : nom illisible |
| trafic réseau | — | — | — | **aucune capture dans la collecte** |

## Les supports amovibles

La chaîne complète, dans l'ordre où le noyau l'écrit :

| question | trace | lu | remarque |
|---|---|---|---|
| branchement, date | `usb 1-2: New USB device found, idVendor=…` | oui | l'instant du branchement |
| **numéro de série** | `usb 1-2: SerialNumber: 4C53…` | oui | **la pièce d'identité du support** — c'est elle qui permet de dire que la même clé a servi ailleurs |
| modèle, fabricant | `Product:`, `Manufacturer:` | oui | facts distincts du numéro de série |
| appareil obtenu | `[sdb] Attached SCSI removable disk` | oui | relie la clé à `/dev/sdb` |
| **par qui** | `Mounted /dev/sdb1 at /run/media/<compte>/…` | oui, **le compte est extrait du chemin** | attribution la plus directe |
| par qui (variante) | `on behalf of uid 1000` | oui | à croiser avec `/etc/passwd` |
| débranchement | `usb 1-2: USB disconnect` | oui | donne la durée de présence |
| ce qui a été lu ou copié dessus | chemins `/run/media/…` dans la timeline et `recently-used.xbel` | oui | **c'est ainsi qu'on montre une copie** |
| contenu de la clé | — | — | — | la clé n'est pas dans la collecte |

**Si le poste n'a pas d'environnement graphique**, il n'y a pas de
`/run/media/<compte>/` : l'attribution passe alors par le recoupement avec la
session ouverte à cet instant. C'est un rapprochement, pas une preuve directe,
et le rapport doit le dire.

## Ce qui a été tapé

| fichier | ce qu'il contient | lu | **daté ?** |
|---|---|---|---|
| `.bash_history`, `.zsh_history` | les commandes du shell | oui | **non par défaut**. Avec `HISTTIMEFORMAT`, des lignes `#<epoch>` : l'extraction les détecte, dit lequel des deux cas, et ne date une commande que si la ligne existe |
| `.python_history`, `.mysql_history`, `.psql_history` | commandes de ces outils | oui | non |
| `.lesshst`, `.wget-hsts` | fichiers ouverts par `less`, hôtes vus par `wget` | oui (comptés) | non |
| `.viminfo` | fichiers ouverts dans vim | oui | garde le chemin **après suppression** |
| `recently-used.xbel` | fichiers ouverts par les applications GTK | oui | **daté** |

Un historique **absent** sur un compte qui a servi est un fait en soi : il est
effaçable par son propriétaire.

## La navigation

| question | trace | lu | limite |
|---|---|---|---|
| pages visitées (Firefox) | `moz_places` de `places.sqlite` | oui | dernière visite seulement |
| téléchargements (Firefox) | `moz_annos` `file://` | oui | |
| pages visitées (Chrome) | table `urls` de `History` | oui | dates depuis **1601** |
| téléchargements (Chrome) | table `downloads` | oui | donne le fichier **et** la page d'origine |
| visites les plus récentes | `places.sqlite-wal` | **non** — signalé comme limite | le navigateur tournait pendant la prise |
| onglets ouverts | `recovery.jsonlz4` | **non** | format LZ4 propriétaire, hors bibliothèque standard |
| cookies, mots de passe | `cookies.sqlite`, `Login Data` | **collectés, non branchés** | lisibles : à demander si besoin |

## Les paquets

| question | trace | lu |
|---|---|---|
| installés maintenant | `rpm -qa --last`, `dpkg -l` | oui |
| **posés puis retirés** | `yum.log`, `dnf.log`, `history.sqlite` | oui — seule trace d'un paquet absent de la liste |
| dépôts ajoutés | `etc/yum.repos.d`, `sources.list.d`, `etc/zypp/repos.d` | **collectés, non analysés** | un dépôt ajouté par un intrus s'y verrait |
| commandes apt datées | blocs `Start-Date`/`Commandline` de `apt/history.log` | oui | ce que l'administrateur a réellement tapé |
| snap installés (Ubuntu) | `var/lib/snapd/state.json` | **collecté, non analysé** | révisions et dates d'installation |
| flatpak installés | `var/lib/flatpak/repo/config` | **collecté, non analysé** | |
| paquets zypper (openSUSE) | `var/log/zypp/history` | collecté, retraits lus | |

## La posture de sécurité

| question | trace | pièce | lu |
|---|---|---|---|
| pare-feu | `firewalld`, `ufw`, `iptables`, `nftables` | `RESEAU/…_reseau.tar.gz` | **collecté, non analysé** |
| SELinux (Fedora, RHEL) | `etc/selinux/config` | `COMPTES/…_droits.tar.gz` | **collecté, non analysé** |
| AppArmor (Ubuntu, SUSE) | `etc/apparmor.d/` | idem | **collecté, non analysé** |

## Le disque

| question | trace | lu | limite |
|---|---|---|---|
| tout ce qui a bougé | `TIMELINE/…_mactime.csv` | oui, filtré sur les chemins sensibles | fuseau de la collecte |
| dates de création | corps lu sur le périphérique | oui | `-1` si le volume a été lu par `find` |
| fichiers supprimés | `SUPPRIMES/<volume>/` | comptés | rendus **par blocs**, suivis de zéros |
| fichiers sans inode | `PHOTOREC/<volume>/` | comptés | ni nom ni date |
| persistance | `PERSISTANCE/…tar.gz` | oui (cron, `ld.so.preload`) | |

## Ce qu'aucune pièce ne dit

À écrire dans « Les limites » quand la question se pose :

- **qui était au clavier** — un compte a agi, c'est tout ;
- **la mémoire vive** — aucun processus, aucune connexion établie, aucune clé ;
- **le trafic réseau** — une IP dans un journal ne dit pas ce qui a transité ;
- **le contenu des dossiers personnels** — `~/Documents`, `~/Téléchargements`
  ne sont pas copiés ; la timeline en donne les noms et les dates ;
- **le contenu d'un support amovible** — la clé n'est pas dans la collecte ;
- **le numéro de série de la machine** — il faut le BIOS, machine allumée. Le
  **modèle**, lui, est dans la ligne `DMI:` que le noyau écrit au démarrage ;
- **ce qui précède la rotation des journaux** — `logrotate` supprime ;
- **ce qui a été écrasé** — un inode qui a resservi ne laisse rien.
