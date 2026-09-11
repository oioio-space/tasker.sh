# Quelle pièce répond à quelle question

Chaque ligne : la question, la pièce dans la collecte, le geste, et sa limite.
Les limites comptent autant que les réponses — c'est ce qui distingue un
rapport d'une affirmation.

**Un tableau par pièce.** Cherchez la vôtre :
`grep -n 'wtmp' references/sources.md`.

## La machine

| question | pièce | geste | limite |
|---|---|---|---|
| nom de la machine | `SYSTEME/hostname` | `cat` | le nom au moment de la collecte, pas forcément celui du domaine |
| système et version | `SYSTEME/os-release` | `grep PRETTY_NAME=` | — |
| machine-id | `SYSTEME/PREFIX_installation.tar.gz` → `etc/machine-id` | `tar -xO` | nomme aussi le dossier du journal systemd : `var/log/journal/<machine-id>/` |
| fuseau du poste | `SYSTEME/PREFIX_localtime.txt` | `readlink /etc/localtime` | si le fichier n'était pas un lien, c'est la règle TZ, moins précise |
| horloge en UTC ou locale | `…installation.tar.gz` → `etc/adjtime` | `tar -xO` | absent sur beaucoup de systèmes : ne concluez rien de son absence |
| date d'installation | `…installation.tar.gz` → `var/log/anaconda/`, `root/*-ks.cfg` | `tar -t`, lecture | **le plus sûr** : ces journaux sont datés du jour de la pose |
| date d'installation (à défaut) | `PAQUETS/PREFIX_paquets.txt` | `rpm -qa --last \| tail` | la salve la plus ancienne. Un système migré ou réinstallé par-dessus fausse la lecture |
| date d'installation (ext seulement) | `SYSTEME/PREFIX_fs_racine.txt` | `grep 'Filesystem created'` | donne la création du système de fichiers, pas de l'OS |
| dernier arrêt | `CONNEXIONS/PREFIX_reboots.txt` | `last -F -x -f wtmp reboot shutdown` | un arrêt brutal n'écrit rien : son absence n'est pas une preuve |
| dernière activité administrative | `PAQUETS/PREFIX_paquets.txt` | `rpm -qa --last \| head` | borne basse seulement |

## Les comptes

| question | pièce | geste | limite |
|---|---|---|---|
| comptes locaux | `COMPTES/passwd` | uid ≥ 1000 et shell interactif | un compte présent n'a pas forcément servi |
| comptes de domaine réellement vus | `COMPTES/PREFIX_domaine.tar.gz` → `var/lib/sss/db/` | `strings` sur le cache | **la pièce maîtresse sur un poste en domaine** : `/etc/passwd` n'a que les comptes locaux |
| droits et sudo | `COMPTES/PREFIX_droits.tar.gz` → `etc/sudoers*` | lecture | — |
| dernière connexion par compte | `CONNEXIONS/lastlog` (ou `lastlog2.db`) | binaire ; sqlite pour lastlog2 | remis à zéro par certaines migrations |
| compte de service avec un shell | `COMPTES/passwd` | uid < 1000 et shell interactif | inhabituel, rarement innocent — mais légitime chez certains éditeurs |

## Le domaine

| question | pièce | geste |
|---|---|---|
| domaine et contrôleurs | `…domaine.tar.gz` → `etc/sssd/sssd.conf` | `grep ad_server`, `ldap_uri` |
| royaume et KDC | `…domaine.tar.gz` → `etc/krb5.conf` | `grep default_realm`, `kdc` |
| adhésion prouvée | `…domaine.tar.gz` → `etc/krb5.keytab` | présence du fichier |
| groupe de travail SMB | `…domaine.tar.gz` → `etc/samba/smb.conf` | `grep workgroup` |
| domaine deviné | `RESEAU/…` → `etc/resolv.conf` | `grep search` | souvent le domaine AD, mais ce n'est qu'un indice |

## Le réseau

| question | pièce | geste | limite |
|---|---|---|---|
| MAC et IP fixes | `RESEAU/PREFIX_reseau.tar.gz` → `etc/NetworkManager/system-connections/*`, `ifcfg-*` | `grep mac-address`, `HWADDR`, `IPADDR` | la configuration, pas l'état au moment des faits |
| IP réellement obtenue | `…reseau.tar.gz` → `var/lib/dhclient/*.leases` | `grep fixed-address` | avec la date du bail : à recouper avec les sessions |
| réseaux sans fil fréquentés | `…reseau.tar.gz` → profils NetworkManager | `grep ssid` | prouve une association, pas une date |
| hôtes contactés en SSH | `…reseau.tar.gz` → `etc/ssh`, et par compte `.ssh/known_hosts` | première colonne | souvent haché (`HashKnownHosts`) : on a l'empreinte, pas le nom |
| DNS, passerelle | `…reseau.tar.gz` → `resolv.conf`, `ifcfg-*` | `grep` | — |
| entrées ajoutées à la main | `…reseau.tar.gz` → `etc/hosts` | lecture | une ligne hors `127.0.0.1` mérite un regard |

## La vie de la machine

| question | pièce | geste | limite |
|---|---|---|---|
| sessions ouvertes | `CONNEXIONS/PREFIX_sessions.txt` | `last -F -f wtmp` | `wtmp` est tourné : la profondeur dépend de `logrotate` |
| échecs d'authentification | `CONNEXIONS/PREFIX_echecs.txt` | `lastb -F -f btmp` | `btmp` est souvent vide ou désactivé |
| démarrages et arrêts | `CONNEXIONS/PREFIX_reboots.txt` | `last -F -x -f wtmp reboot shutdown` | sans `-x`, les arrêts sont invisibles |
| SSH accepté et refusé | `JOURNAUX/PREFIX_journal.txt`, ou `var/log/secure` | `grep Accepted\|Failed` | Fedora n'a pas de `secure` : tout est dans le journal |
| sudo et su | idem | `grep 'COMMAND='`, `session opened for user` | donne le compte, pas la personne |
| USB branchés | `JOURNAUX/PREFIX_journal.txt`, `var/log/messages` | `grep 'New USB device'`, `Attached SCSI removable` | le noyau donne vendeur/produit ; le numéro de série n'est pas toujours journalisé |
| montage d'un support | idem | `grep /run/media` | GNOME monte sous `/run/media/<compte>/<étiquette>` : le compte apparaît dans le chemin |

## Les comptes, en détail

| question | pièce | geste | limite |
|---|---|---|---|
| navigation Firefox | `COMPTES/PREFIX_<compte>_profils.tar.gz` → `.mozilla/…/places.sqlite` | `sqlite3` sur `moz_places` | l'historique peut avoir été vidé |
| téléchargements Firefox | idem | `moz_annos` où `content LIKE 'file://%'` | Firefox récent range aussi dans `moz_places` |
| domaines ayant posé un cookie (Firefox) | `…profils.tar.gz` → `.mozilla/…/cookies.sqlite` | `sqlite3` sur `moz_cookies`, groupé par domaine | **survit au vidage de l'historique** ; la valeur du cookie n'est pas lue |
| domaines ayant posé un cookie (Chrome) | `…profils.tar.gz` → `…/Default/Cookies` ou `…/Default/Network/Cookies` | `sqlite3` sur `cookies`, groupé par domaine | idem ; dates depuis 1601 |
| navigation Chrome | `…profils.tar.gz` → `.config/google-chrome/Default/History` | `sqlite3` sur `urls` | horodatage en microsecondes depuis 1601 |
| téléchargements Chrome | idem | table `downloads` | donne le chemin cible **et** l'URL d'origine |
| fichiers ouverts récemment | `…profils.tar.gz` → `.local/share/recently-used.xbel` | `grep href=` | couvre les applications GTK, pas le terminal |
| commandes tapées | `COMPTES/PREFIX_<compte>_artefacts.tar.gz` → `.bash_history` | lecture | **non daté** par défaut, et effaçable. Ne datez jamais une ligne d'historique sans autre source |
| clés SSH acceptées | `…artefacts.tar.gz` → `.ssh/authorized_keys` | lecture | une clé inconnue permet une entrée sans mot de passe |
| contenu du dossier personnel | `COMPTES/PREFIX_<compte>_inventaire.txt` | `ls -lRa` | les noms et les dates, pas le contenu |

## Le disque

| question | pièce | geste | limite |
|---|---|---|---|
| tout ce qui a bougé, daté | `TIMELINE/PREFIX_mactime.csv` | lecture | dans le fuseau `TZ_MACTIME` de la collecte, pas celui du poste |
| provenance des lignes | `TIMELINE/PREFIX_body*.mactime` | — | `body.mactime` = lu sur le périphérique (dates de création, supprimés) ; `body_imbriques.mactime` = volumes montés dessous |
| fichiers supprimés | `SUPPRIMES/<volume>/` | `ls` | nom = date de suppression + inode. **Rendus par blocs entiers** : le contenu est suivi de zéros |
| fichiers sans inode | `PHOTOREC/<volume>/recup_*/` | `ls` | ni nom ni date d'origine ; seulement les types que photorec connaît |
| persistance | `PERSISTANCE/PREFIX_persistance.tar.gz` | lecture de `cron*`, `systemd`, `ld.so.preload` | `ld.so.preload` non vide est rarissime sur un poste sain |

## Ce que la collecte ne contient jamais

À dire dans « Les limites » quand la question se pose :

- **La mémoire vive** — aucun processus, aucune connexion établie, aucune clé
  de chiffrement. La collecte est faite sur une image montée, froide.
- **Le contenu des dossiers personnels** — seuls les artefacts de triage et les
  profils applicatifs sont emportés. `~/Documents`, `~/Téléchargements` ne sont
  pas copiés : la timeline en donne les **noms et les dates**, pas le contenu.
- **Le trafic réseau** — aucune capture. Une IP dans un journal dit qu'il y a eu
  une connexion, pas ce qui a transité.
- **Ce qui a été écrasé** — un fichier supprimé dont l'inode a resservi ne
  laisse rien, ni à `xfs_undelete`, ni au carving.
- **Les journaux plus vieux que la rotation** — `logrotate` supprime. La
  première date de `wtmp` est une borne du fichier, pas de la machine.
