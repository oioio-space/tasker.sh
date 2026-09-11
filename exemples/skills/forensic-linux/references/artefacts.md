# Ce que sont les artefacts

À lire quand un nom de fichier ne vous dit rien. Vous travaillez **hors ligne** :
rien de ce qui suit ne peut être cherché ailleurs, tout ce qui compte est ici.

Pour chaque pièce : ce que c'est, ce qu'elle **prouve**, ce qu'elle **ne prouve
pas**, et le piège qui fait dire des bêtises.

**Ce fichier est long. N'en lisez qu'une section**, avec
`grep -A 60 '## Les navigateurs' references/artefacts.md` — le nom exact est
dans la colonne de gauche. Le lire en entier coûte huit fois ce qu'une section
coûte, pour une réponse qui tient dans une seule.

| ouvrez… | quand |
|---|---|
| `## Les fichiers de connexion` | `wtmp`, `btmp`, `lastlog`, `wtmp.db`, `lastlog2.db`, la sortie de `last` |
| `## Le journal systemd` | `journal.txt`, les journaux binaires, `journalctl` |
| `## Les traces d'un compte` | `.bash_history`, `.ssh`, `recently-used.xbel`, les profils applicatifs |
| `## Les navigateurs` | `places.sqlite`, `History`, `Cookies`, `logins.json`, `Bookmarks`, `Web Data` |
| `## Le réseau` | `NetworkManager`, `ifcfg`, `resolv.conf`, `hosts`, `known_hosts`, les baux DHCP |
| `## Le domaine` | `sssd`, `krb5.conf`, `samba`, le cache sss |
| `## Le disque` | `fstab`, les systèmes de fichiers, `SUPPRIMES/`, `PHOTOREC/` |
| `## Les paquets` | `dpkg`, `rpm`, `pacman`, `apk`, `snap`, `flatpak`, les dépôts |
| `## La timeline mactime` | `mactime.csv`, les drapeaux `macb`, les inodes |
| `## Les pièces qu'on oublie` | `machine-id`, `adjtime`, `localtime`, les journaux d'installation |
| `## STRINGS/` | les chaînes lisibles des périphériques, et leurs extraits |
| `## PLASO/ — la super-timeline` | `plaso.jsonl`, `psort`, `log2timeline`, les `data_type` |

---

## Les fichiers de connexion

### `wtmp`
Un fichier **binaire** où le système écrit une ligne à chaque ouverture et
fermeture de session, à chaque démarrage et à chaque arrêt. Se lit avec `last`.

- **Prouve** : qu'une session a été ouverte au nom d'un compte, depuis un
  terminal ou une adresse, entre deux instants.
- **Ne prouve pas** : qui était devant le clavier ; ni qu'il ne s'est rien passé
  en dehors des périodes listées.
- **Piège** : `logrotate` le tronque périodiquement. La première ligne donne
  l'âge du **fichier**, pas celui de la machine. Un `wtmp` qui commence il y a
  trois jours ne dit rien des trois mois précédents.
- **Piège** : un arrêt brutal (coupure, plantage) n'écrit rien. Une session sans
  fermeture n'est pas une session encore ouverte.

### `btmp`
Le même, pour les **échecs** d'authentification. Se lit avec `lastb`.

- **Prouve** : qu'un mot de passe erroné a été présenté pour un nom donné.
- **Piège** : souvent vide, parfois désactivé — son absence ne prouve aucune
  absence d'attaque. Et le « nom » d'un échec SSH est celui **tenté**, pas un
  compte existant : `admin` dans `btmp` ne veut pas dire qu'un compte `admin`
  existe.

### Le format binaire, et pourquoi il est lu directement
`wtmp` et `btmp` sont des suites d'enregistrements de **384 octets**
(`struct utmp`, Linux 64 bits) ; `lastlog`, de **292 octets** indexés par uid.
La collecte les copie **et** en tire une version texte avec `last`. L'analyse
lit le texte quand il est là, le binaire sinon — donc même si `last` manquait
au moment de la collecte, ou si l'image n'avait que le binaire.

Le binaire a un avantage : ses dates sont des **epoch**, sans langue ni année à
deviner. Elles sont rendues en **UTC**, suffixées d'un `Z`.

Un fichier dont la taille n'est pas un multiple de 384 est signalé comme
illisible plutôt qu'ignoré : autre architecture, ou fichier tronqué.

### `lastlog` / `lastlog2.db`
La **dernière** connexion de chaque compte, une entrée par compte, écrasée à
chaque fois. `lastlog` est binaire et indexé par uid ; sur Fedora 40 et Debian
13, il est remplacé par `lastlog2.db`, une base SQLite.

- **Prouve** : la date de dernière connexion — et donc qu'un compte a servi
  au moins une fois.
- **Ne prouve pas** : le nombre de connexions, ni les précédentes.

---

## Le journal systemd

### `var/log/journal/<machine-id>/*.journal`
Le journal binaire de systemd. La collecte l'exporte en clair dans
`JOURNAUX/PREFIX_journal.txt`, au format `short-iso` : une date ISO avec
décalage, la machine, le programme, le message.

- **Contient** : authentifications (`sshd`), élévations (`sudo`, `su`),
  branchements matériels (messages du noyau), montages, services.
- **Piège** : Fedora et les dérivés récents n'installent **pas** rsyslog. Il n'y
  a alors ni `/var/log/secure`, ni `messages`, ni `auth.log` : tout est là, et
  seulement là.
- **Piège** : le journal est limité en taille (`SystemMaxUse`). Les entrées
  anciennes sont supprimées sans trace.
- **Vérification** : la collecte lance `journalctl --verify` ; son résultat est
  dans la sortie de l'étape.

### `var/log/secure`, `auth.log`, `messages`, `syslog`
Les journaux texte classiques (RHEL utilise `secure`, Debian `auth.log`).
Format « syslog » : `Sep  2 11:44:03 machine programme[pid]: message`.

- **Piège majeur** : **l'année n'y figure pas.** Un fichier tourné en janvier
  contient des dates de décembre sans année. Ne datez jamais une ligne syslog à
  l'année près sans la recouper avec la date du fichier ou le journal systemd.

---

## Les traces d'un compte

### `.bash_history`, `.zsh_history`
Les commandes tapées dans un shell.

- **Prouve** : que ces commandes ont été **écrites** dans le fichier d'un compte.
- **Ne prouve pas** : quand. **Le format par défaut n'a aucune date.**
  (Avec `HISTTIMEFORMAT`, bash écrit une ligne `#<epoch>` avant chaque commande :
  si vous voyez ces lignes, les dates existent. Sinon, non.)
- **Ne prouve pas** : que la commande a réussi, ni même qu'elle a été lancée —
  une ligne peut avoir été tapée puis annulée.
- **Piège** : l'ordre est celui de l'écriture, et l'écriture a lieu **à la
  fermeture du shell**. Deux terminaux ouverts en parallèle entrelacent mal.
  Le fichier est effaçable par son propriétaire (`history -c`), et son absence
  sur un compte qui a servi est en soi un fait.

### `.ssh/known_hosts`
Les machines auxquelles ce compte s'est connecté en SSH depuis ce poste.

- **Prouve** : une connexion sortante réussie vers cet hôte, au moins une fois.
- **Piège** : souvent **haché** (`HashKnownHosts yes` par défaut sur Ubuntu) :
  les lignes commencent par `|1|` et le nom d'hôte est illisible. On sait qu'il y
  a eu des connexions, on ne sait pas vers quoi. La date, elle, n'y est jamais —
  seule la date de modification du fichier borne la dernière.

### `.ssh/authorized_keys`
Les clés publiques autorisées à **ouvrir** ce compte sans mot de passe.

- **Prouve** : que le détenteur de la clé privée correspondante pouvait entrer.
- **À regarder** : le commentaire en fin de ligne (`utilisateur@machine`) donne
  souvent l'origine. Une clé dont le commentaire ne correspond à aucun poste
  connu est un fait notable.

### `.local/share/recently-used.xbel`
Les fichiers récemment ouverts par les applications GTK (GNOME, LibreOffice,
visionneuses). XML, avec les dates d'ajout et de modification.

- **Prouve** : qu'un fichier a été **ouvert** par une application graphique.
- **Ne prouve pas** : par le terminal, ni par une application non GTK.
- **Très utile** : garde le chemin même après suppression du fichier, et
  notamment les chemins sous `/run/media/…` — donc ce qui a été ouvert **depuis
  une clé USB**.

---

### `wtmp.db` (wtmpdb) et `lastlog2.db`
Depuis Fedora 40 et Debian 13, ces bases **SQLite** remplacent les binaires.
`wtmp.db` a une table `wtmp` (User, Login, Logout, TTY, RemoteHost),
`lastlog2.db` une table `Lastlog2` (Name, Time, TTY, RemoteHost). Dates en
epoch. La collecte les copie et les vide aussi en texte ; l'analyse lit la
base, plus fidèle qu'un dump SQL.

## Les navigateurs

### `places.sqlite` (Firefox)
Base SQLite du profil Firefox, dans `.mozilla/firefox/<aléatoire>.default*/`.

- Table `moz_places` : les URL connues, avec `last_visit_date`.
- Table `moz_historyvisits` : chaque visite, avec son type.
- Table `moz_annos` : les annotations, dont les **téléchargements** — la ligne
  dont `content` commence par `file://` donne le chemin où le fichier a atterri.
- **Dates** : microsecondes depuis le 1ᵉʳ janvier 1970.
  `datetime(valeur/1000000,'unixepoch')` rend une date lisible, **en UTC**.
- **Piège** : `last_visit_date` est écrasé à chaque visite : on a la dernière,
  pas la première. `moz_historyvisits` garde le détail — utilisez-la si elle est
  présente.
- **Piège** : l'historique peut avoir été vidé ; le fichier existe alors, vide.
- **Piège majeur** : un fichier `places.sqlite-wal` **non vide** à côté signifie
  que le navigateur tournait quand l'image a été prise. Les visites les plus
  récentes sont dans ce journal d'écriture, **pas dans la base** — et l'analyse
  ne les voit pas. Le cas est signalé comme une limite, jamais passé sous
  silence. Même chose pour un `-journal` à côté d'un `History` Chrome.

### `cookies.sqlite` (Firefox)
Base SQLite du profil, **indépendante de l'historique**. Table `moz_cookies` :
`host` (le domaine), `name`, `value`, `creationTime`, `lastAccessed`, `expiry`.
Dates en microsecondes depuis 1970, comme `places.sqlite`.

- **Pourquoi elle compte** : vider l'historique n'efface pas les cookies. Un
  domaine présent ici et absent de `places.sqlite` est une **visite dont la
  trace d'historique a disparu** — et c'est un fait notable en soi.
- **Ce qui est extrait** : le domaine, le nombre de cookies, la date du premier
  posé et celle du dernier accès, regroupés par domaine. Un profil en compte
  des milliers ; le détail cookie par cookie n'apprend rien de plus.
- **Ce qui n'est PAS extrait, volontairement** : la colonne `value`. C'est un
  jeton de session, donc un identifiant réutilisable — le sortir ferait du
  rapport un secret à protéger, sans rien ajouter à la démonstration. Si une
  procédure l'exige, c'est une décision à prendre explicitement, pas un défaut
  de l'outil.

### `History` (Chrome / Chromium / Edge)
Base SQLite, dans `.config/google-chrome/Default/` ou `.config/chromium/Default/`.

- Table `urls` : URL, titre, `visit_count`, `last_visit_time`.
- Table `downloads` : `target_path` (où le fichier a été écrit), `tab_url`
  (**la page depuis laquelle il a été demandé**), `start_time`, `total_bytes`.
- **Dates** : microsecondes depuis le **1ᵉʳ janvier 1601**. Il faut retrancher
  11 644 473 600 secondes :
  `datetime(valeur/1000000-11644473600,'unixepoch')`, en UTC.
  Une date de 1601 dans un rapport signale une conversion oubliée.
- **La table `downloads` est la meilleure pièce** pour un téléchargement : elle
  donne à la fois le fichier, sa provenance et l'heure.

### `Cookies` (Chrome / Chromium / Edge)
Base SQLite nommée `Cookies`, **sans extension**. Depuis Chrome 96 elle est
sous `Default/Network/`, avant sous `Default/` — les deux sont lues. Table
`cookies` : `host_key`, `name`, `creation_utc`, `last_access_utc`,
`expires_utc`, et `encrypted_value`.

- Mêmes usages que côté Firefox : un domaine ici et absent de `urls` est une
  visite dont la trace d'historique a disparu.
- **Dates depuis 1601**, comme `History`.
- La valeur est **chiffrée** (`v10`/`v11`) par le trousseau du bureau — elle
  serait illisible sans la clé, et elle n'est de toute façon pas extraite.

---

## Le réseau

### `etc/NetworkManager/system-connections/*.nmconnection`
Un profil de connexion, en INI. `[ethernet] mac-address=`,
`[ipv4] address1=`, `[wifi] ssid=`.

- **Prouve** : que la machine a été configurée pour ce réseau — et pour un SSID,
  qu'elle s'y est associée au moins une fois (NetworkManager n'écrit un profil
  qu'après une association réussie).
- **Ne prouve pas** : la date. Le profil n'en porte pas ; seule la date de
  modification du fichier, visible dans la timeline, en donne une.

### `etc/sysconfig/network-scripts/ifcfg-*` (RHEL/CentOS)
L'ancienne forme : `DEVICE=`, `HWADDR=` (l'adresse MAC), `IPADDR=`,
`GATEWAY=`, `DNS1=`.

### `var/lib/dhclient/*.leases`, `var/lib/NetworkManager/*.lease`
Les **baux DHCP** : `fixed-address` donne l'IP réellement obtenue,
`option dhcp-server-identifier` le serveur, et le bail porte des **dates**.

- **La meilleure pièce réseau** : contrairement à la configuration, un bail
  prouve que la machine était **branchée et active** à cette date, sur ce
  réseau-là.

### `etc/resolv.conf`
`nameserver` (les DNS) et `search` (le domaine de recherche).

- Sur un poste en domaine, `search` est presque toujours le domaine Active
  Directory, et les `nameserver` sont les contrôleurs. Indice fort, pas preuve.

### `etc/hosts`
Correspondances nom → adresse posées à la main. Toute ligne autre que
`127.0.0.1`, `::1` et le nom de la machine mérite un regard : c'est ainsi qu'on
détourne un nom vers un serveur choisi.

---

## Le domaine

### `etc/sssd/sssd.conf`
La configuration de SSSD, qui relie le poste à un annuaire.
`domains =`, `id_provider = ad|ldap|ipa`, `ad_server =`, `ldap_uri =`.

### `etc/krb5.conf`
Kerberos. `default_realm` (le royaume, en majuscules), `kdc =` (les contrôleurs).

### `etc/krb5.keytab`
Le secret de la **machine** dans le domaine. Sa présence prouve que le poste
était réellement joint, pas seulement configuré pour l'être.

### `var/lib/sss/db/cache_*.ldb`
**La pièce maîtresse sur un poste en domaine.** Le cache de SSSD : les comptes
du domaine qui ont été résolus ou connectés **sur cette machine**.

- Pourquoi elle compte : `/etc/passwd` ne contient que les comptes **locaux**.
  Sur un poste en entreprise, les vrais utilisateurs n'y sont **pas**. Sans ce
  cache, un rapport conclurait « deux comptes » sur une machine qui en a vu
  trente.
- Se lit avec `strings` : les entrées ont la forme `name=<compte>,cn=users,cn=<DOMAINE>`.
- **Ne prouve pas** une connexion : une simple résolution de nom (un `ls -l`
  affichant un propriétaire) remplit aussi le cache. À recouper avec `wtmp`.

---

## Le disque

### `PREFIX_body.mactime` et `PREFIX_body_imbriques.mactime`
Les « corps » : une ligne par fichier, onze champs séparés par `|` —
`0|chemin|inode|droits|uid|gid|taille|atime|mtime|ctime|crtime`.

- `body.mactime` vient du **périphérique** : il contient les dates de création
  et, sur ext, les **entrées supprimées**.
- `body_imbriques.mactime` couvre ce qui était monté dessous (un `/home` sur un
  autre volume).
- Une valeur `-1` en dernière colonne signifie **pas de date de création** : le
  volume a été lu par `find` faute de lecteur, pas sur le périphérique.

### `PREFIX_mactime.csv`
La chronologie tirée des corps. Colonnes : date, taille, **type**, droits, uid,
gid, inode, chemin.

- Le champ **type** est la clé : `m` = contenu modifié, `a` = lu (accédé),
  `c` = métadonnées changées (droits, nom, place), `b` = créé.
  `macb` sur une seule ligne = les quatre au même instant, c'est-à-dire une
  **création**. Un `..c.` isolé signale un `chmod`, un `mv` ou un `chown`.
- **Piège** : la date est écrite dans le fuseau passé à `TZ_MACTIME` lors de la
  collecte, souvent UTC — pas dans le fuseau du poste analysé.
- **Piège** : `atime` n'est pas fiable. La plupart des systèmes montent avec
  `relatime` : la date de lecture n'est mise à jour qu'une fois par jour. Une
  absence de lecture ne prouve rien.

### `SUPPRIMES/<volume>/`
Ce que `xfs_undelete` a rendu. Nom = `AAAA-MM-JJ-HH-MM_<inode>.<type>`, où la
date est le **ctime de l'inode**, c'est-à-dire l'instant de la suppression.

- **Piège** : le contenu est rendu **par blocs entiers**. Un fichier de 1 235
  octets ressort à 4 096, suivi de zéros. Ne comparez pas une empreinte à celle
  de l'original sans tronquer.

### `PHOTOREC/<volume>/recup_*/`
Le carving : des fichiers reconnus par leur **signature** dans les octets bruts.

- **Sans nom d'origine, sans chemin, sans date.** Le nom est un numéro.
- Ne trouve que les types qu'il connaît : un texte, une base maison sont
  invisibles. En revanche il retrouve ce dont **plus aucun inode ne parle**.

### `PREFIX_persistance.tar.gz`
Ce qui se relance tout seul : `cron`, unités systemd, `rc.local`, `profile.d`,
`ld.so.preload`, règles `udev`.

- `etc/ld.so.preload` **non vide** est rarissime sur un poste sain : la
  bibliothèque nommée est chargée dans **tous** les programmes. À examiner en
  premier.
- Une tâche `cron` qui télécharge et exécute (`curl … | sh`) n'a pas
  d'explication innocente courante.

---

## Les paquets

### `PREFIX_paquets.txt`
La sortie de `rpm -qa --last` ou `dpkg-query -l`.

- Avec `--last`, chaque ligne porte la date d'installation, du plus récent au
  plus ancien. **La dernière ligne date l'installation du système** : c'est la
  salve initiale.
- **Piège** : les dates sont écrites dans la **langue du poste collecteur**
  (« mar. 27 août 2019 »). L'extracteur les lit sans dépendre de la locale ;
  si vous lisez le fichier à la main, n'en soyez pas surpris.

### Les journaux tournés : `.gz`, `.xz`, `.bz2`, `.zst`
`logrotate` comprime les anciens journaux. `gzip` est le défaut, mais `xz` et
`bzip2` se rencontrent, et `zstd` sur les distributions récentes. Les trois
premiers s'ouvrent avec la bibliothèque standard de Python ; `zstd` demande
Python 3.14 ou le paquet `zstandard`. Quand un journal ne peut pas être ouvert,
c'est **écrit comme une limite** — un journal non lu ne doit jamais passer pour
un journal sans rien dedans.

### `PREFIX_historique.tar.gz`
Les journaux du gestionnaire de paquets : `yum.log`, `dnf.log`,
`history.sqlite`, `dpkg.log`, `apt/history.log`.

- **Ce que `rpm -qa` ne dit pas** : un paquet installé **puis retiré**. Ces
  journaux gardent la trace des suppressions (`Erased:`, `remove`).

## La timeline mactime — la pièce qui confirme les autres

`TIMELINE/PREFIX_mactime.csv` porte **une ligne par date de chaque fichier** du
disque : `Date,Size,Type,Mode,UID,GID,Meta,File Name`. Sur un poste ordinaire,
des millions de lignes — elle ne se lit pas, elle **se questionne**.

La colonne `Type` est le cœur : quatre lettres **MACB**, celles qui s'appliquent
à cette date.

| lettre | ce qui a changé | ce que ça montre |
|---|---|---|
| `m` | le contenu (*modify*) | une écriture |
| `a` | le dernier accès (*access*) | une lecture — souvent désactivée (`noatime`) : son absence ne prouve rien |
| `c` | l'inode (*change*) : droits, nom, propriétaire | un `chmod`, un `mv`, une copie qui pose ses droits |
| `b` | la naissance (*birth*) | la **création** du fichier — ext4, XFS et btrfs la gardent, pas ext3 |

Un fichier qui apparaît **`...b` sous `/run/media/<compte>/`** pendant que la clé
était montée, c'est une **copie vers le support**. Le même fichier `.a..` seul,
c'est une lecture. C'est la différence entre « une clé a été branchée » et « ce
fichier en est parti ».

**La colonne `Meta` est l'inode.** Deux chemins de même inode sont le même
fichier — un lien, ou un `mv`. Un inode réutilisé après suppression porte les
dates du nouveau fichier : une date antérieure à la création apparente est
normale, pas une manipulation.

**Le fuseau.** mactime écrit ses dates dans le fuseau qu'on lui passe (`-z`),
`UTC` par défaut dans `collecte-linux.conf`, et la collecte le note à côté dans
`PREFIX_fuseau_timeline.txt`. Sans ce fichier — collecte ancienne — les dates de
la timeline sont d'un fuseau inconnu : **ne les comparez pas à celles du journal
sans le dire.**

**Ce que l'extraction en tire.** Elle ne recopie pas la timeline. Elle lui pose
les questions que les autres pièces ont soulevées : le fichier annoncé par le
navigateur est-il sur le disque, et quand y est-il apparu ? qu'a-t-on écrit ou
lu sous le point de montage du support amovible ? Chaque réponse est un fait qui
porte `confirme: F0123` — l'identifiant du fait qu'elle confirme. Un
téléchargement **non** retrouvé est un fait aussi : effacé depuis, renommé, ou
sur un volume que la timeline ne couvre pas.

## Les pièces qu'on oublie, et ce qu'elles disent

Ce que la collecte emporte au-delà des grands classiques, et pourquoi chacune
mérite d'être lue.

| pièce | où | ce qu'elle établit | ce qu'elle n'établit pas |
|---|---|---|---|
| **marque-pages** (`moz_bookmarks` de `places.sqlite`, `Bookmarks` de Chrome en JSON) | profil du compte | un choix **délibéré**, **daté** (`dateAdded`), qui **survit au vidage de l'historique** — ce que l'utilisateur croit souvent suffisant | que le site ait été visité récemment : un signet peut dormir des années |
| **historique de formulaire** (`formhistory.sqlite`, table `autofill` de `Web Data`) | idem | ce que le compte a **tapé** : recherches, adresses, identifiants de connexion — l'intention, là où l'historique ne donne que le résultat | le mot de passe : il n'est pas dans ces tables. Une valeur peut avoir été saisie sur n'importe quel site |
| **recherches de la barre d'adresse** (`keyword_search_terms`) | `History` de Chrome | le terme saisi et la page atteinte, datés | ce que Firefox a cherché : il garde ses recherches dans l'historique de formulaire |
| **applications snap et flatpak** (`~/snap/<app>/`, `~/.var/app/<id>/`) | archive de profil, **par les noms des membres** | qu'une application est **présente chez ce compte** alors qu'**aucune liste de paquets ne la montre** — un snap échappe à `dpkg` comme à `rpm` | qu'elle ait servi, ni qui l'a installée. Le dossier peut survivre à la désinstallation |
| **unités systemd** (`ExecStart=`) | archive de persistance | ce qui se relance seul. Une unité dans `/etc/systemd/system` a été posée **à la main** ; celles de `/usr/lib` viennent des paquets et sont comptées, pas listées | qu'elle ait démarré : le journal le dit, pas le fichier |
| **autostart** (`.desktop` avec `Exec=`) | `/etc/xdg/autostart`, et `~/.config/autostart` **par compte** | un programme lancé à l'ouverture de session — celui du dossier personnel est **propre à ce compte** | qui l'y a mis |
| **règles udev** (`RUN+=`) | archive de persistance | un programme déclenché au **branchement d'un matériel** | son exécution |
| **kickstart** (`anaconda-ks.cfg`) | archive d'installation | la configuration **d'origine** : nom donné, fuseau, comptes créés à la pose, mot de passe root chiffré ou non | ce qui a changé depuis |
| **Thunderbird** (`prefs.js`) | profil du compte | les **adresses de courriel** et les serveurs configurés — une adresse personnelle à côté de l'adresse professionnelle est un fait | ce qui a été envoyé ou reçu |
| **sortie de photorec** | `PHOTOREC/` | des contenus effacés, **par type** (document, image, archive, secret possible) | **ni le nom, ni la date, ni le chemin** d'origine. Le type vient de l'extension que photorec devine. Une empreinte ou une chaîne connue s'y cherche avec `--indicateurs` |
| **`/etc/fstab`** | `SYSTEME/fstab` | les volumes que la machine **déclarait** — y compris un partage réseau ou un volume chiffré absent de la collecte | qu'ils aient été montés |
| **disques de machines virtuelles** (`.vmdk`, `.qcow2`…) | `MACHINES/` | qu'une VM vit sur ce poste : **elle emporte son propre système**, et ce qu'on y a fait n'est dans aucune de ces pièces | son contenu, qui demande une collecte à part |



## PLASO/ — la super-timeline

`log2timeline` parcourt l'image et rend un **événement daté par artefact
reconnu** ; `psort -o json_line` les écrit à la suite, un JSON par ligne. C'est
la pièce la plus riche d'une collecte.

**Ce qu'elle apporte par rapport à `mactime`.** mactime ne connaît que les
quatre dates du système de fichiers (`macb`). plaso, lui, OUVRE les pièces :
bases de navigateur, journaux systemd et syslog, caches d'applications,
fichiers de configuration, corbeilles, historiques de connexion. Une question
sans réponse ailleurs — « quand ce signet a-t-il été posé », « qu'est-ce qui a
tourné à 3 h du matin » — a souvent la sienne ici.

**Ce qu'elle ne prouve pas.** Un événement plaso est une LECTURE d'un artefact,
avec les mêmes limites que l'artefact lui-même : un `fs:stat` ne dit pas qui a
écrit le fichier, un `syslog:line` porte l'heure du poste sans fuseau. Le champ
`timestamp_desc` dit CE QUE la date signifie (`mtime`, `crtime`, « Start
Time »…) : il n'est pas décoratif, et deux événements du même fichier à deux
dates différentes sont deux faits différents.

**Où elle la cherche.** Nulle part en particulier. Le nommage d'une collecte
n'est jamais parfait — le dossier peut s'appeler `PLASO`, `plaso`,
`TIMELINE_PLASO` ou rien du tout, et le fichier `plaso.jsonl`,
`super_timeline.json`, `l2t.jsonl.gz`, `PC01-psort.json`. L'extraction ne se fie
donc PAS au nom : elle retient les candidats bon marché — tout `.json` ou
`.jsonl`, comprimé ou non, hors de `PHOTOREC/` et `SUPPRIMES/` —, puis OUVRE la
première ligne de chacun et regarde si c'est du plaso. Les deux sorties de psort
sont acceptées : `-o json_line` (un objet par ligne) et `-o json` (un unique
tableau). Un `state.json` de snapd, ou nos propres `faits.jsonl`, sont écartés.

Si votre super-timeline n'est pas vue, c'est que sa première ligne ne porte pas
deux des champs `data_type`, `timestamp_desc`, `parser`, `__container_type__`,
`pathspec`, `display_name`, `timestamp`, `date_time` — regardez-la
(`head -1 … | python3 -m json.tool`) avant de conclure.

**Ce que l'extraction en fait — et ne fait pas.** Une super-timeline compte des
millions de lignes ; les recopier en faits n'apprendrait rien et noierait le
rapport. `extraire.py` en tire quatre choses :

1. un **recensement** — combien d'événements, sur quelle période, combien de
   familles d'artefact (`data_type`) et d'analyseurs (`parser`), avec les 25
   familles les plus nombreuses. C'est lui qui dit ce que la pièce PEUT
   répondre : lisez-le avant de lui demander quoi que ce soit ;
2. les **questions déjà posées** par les autres faits — un fichier téléchargé,
   un point de montage amovible — rejouées sur plaso, avec la même exigence que
   sur mactime : « fichier retrouvé » vaut **au chemin annoncé**, « fichier de
   MÊME NOM » est une homonymie, sans acteur ;
3. les **chemins sensibles**, bornés à 300, et la borne se dit ;
4. un fait `limite` comptant les lignes qu'il n'a pas su lire ou dater.

**Et trois RECOUPEMENTS avec le reste des faits** — c'est là qu'une
super-timeline vaut plus que la somme de ses lignes :

- **par session.** Chaque ouverture de session établie ailleurs (wtmp, `last`)
  donne une fenêtre ; l'extraction compte les événements plaso qui y tombent.
  Le fait porte l'acteur et cite le fait d'ouverture. Quand la pièce ne donne
  pas la fermeture, la fenêtre est **bornée** à seize heures et le fait le dit :
  elle n'est pas mesurée. Attention au sens : un événement dans la fenêtre d'une
  session n'est pas l'œuvre de ce compte — un service tourne aussi pendant qu'il
  est connecté. C'est un rapprochement, à confirmer sur la pièce.
- **par compte.** Les événements sous `/home/<compte>/` et `/root/` sont comptés
  et datés par compte. Même réserve : un service écrit aussi chez les gens.
- **par intervalle.** Les journées qui portent au moins un événement sont
  relevées, et tout intervalle de plus de sept jours sans un seul événement
  devient un fait. C'est ce qui permet de peser un « rien entre le X et le Y » :
  la synthèse des périodes ne voit que les faits des autres phases, alors que
  plaso a lu les bases, les journaux et les caches. Un intervalle vide **ici**
  pèse bien plus lourd — sans dire pour autant que le poste n'a pas servi.

**Pour le reste, interrogez le fichier vous-même.** Il est fait pour :

    jq -r .data_type PLASO/*.jsonl | sort | uniq -c | sort -rn | head -30
    jq -r 'select(.data_type=="chrome:history:page_visited") | [.timestamp, .url] | @tsv' PLASO/*.jsonl
    jq -r 'select(.timestamp > 1767600000000000 and .timestamp < 1767686400000000) | .message' PLASO/*.jsonl

Sans `jq`, `grep '"data_type": "syslog:line"'` fait l'affaire : une ligne est un
événement, le fichier se découpe au `grep` sans rien casser.

**Le piège du format.** Le schéma de `psort -o json_line` a CHANGÉ selon les
versions de plaso : l'horodatage est tantôt `timestamp` en microsecondes depuis
1970, tantôt `date_time.timestamp` en secondes, tantôt une chaîne ISO dans
`datetime`. L'extraction accepte les trois et COMPTE ce qu'elle n'a pas su
dater. Si le fait « lignes plaso non exploitées » annonce un nombre élevé, c'est
que votre version écrit une quatrième forme : regardez une ligne
(`head -1 PLASO/*.jsonl | python3 -m json.tool`) avant de conclure quoi que ce
soit sur le contenu.

**Le chemin.** `display_name` porte le préfixe du conteneur — `TSK:/etc/passwd`,
`GZIP:/var/log/x`, `OS:/home/…`. L'extraction le retire pour pouvoir comparer
avec les chemins des autres faits ; si vous comparez à la main, retirez-le
aussi, sans quoi rien ne correspondra jamais.

---
## STRINGS/ — les chaînes lisibles des périphériques

Un jeu de fichiers par volume monté sous le point de montage de l'analyse, la
racine comme un `/home` posé sur un autre disque. La liste est celle qui sert à
photorec : aucun volume ne peut être oublié, aucun n'est nommé à la main.

    PREFIX_strings_<volume>.txt           les chaînes brutes, non comprimées
    PREFIX_strings_<volume>_urls.txt      les adresses web, comptées
    PREFIX_strings_<volume>_courriels.txt les adresses de courriel
    PREFIX_strings_<volume>_ip.txt        les adresses IP
    PREFIX_strings_<volume>_mac.txt       les adresses MAC
    PREFIX_strings_<volume>_chemins.txt   les chemins sous /home, /root, /media…

Les cinq extraits sont au format `compte valeur` : le nombre d'occurrences,
puis la chaîne, les plus fréquentes d'abord. Le compte dit à lui seul si une
chaîne traîne partout ou n'apparaît qu'une fois.

**`strings` est appelé NU, sans une seule option.** La pièce est donc le texte
brut du périphérique tel que l'outil le rend par défaut, et un lecteur qui veut
la refaire tape exactement la même commande. Ce que cela implique :

- **aucun décalage en octets.** On sait qu'une chaîne est sur le volume ; on ne
  peut pas dire où. Pour situer une occurrence, il faut revenir au fichier brut
  et l'y chercher.
- **longueur minimale de 4 caractères** (le défaut) au lieu de 8 : beaucoup
  plus de bruit binaire dans le fichier comme dans les extraits.
- **pas de compression** : la sortie d'un disque se compte en dizaines de
  gigaoctets, là où le texte se comprimait d'un facteur cinq à dix. Prévoyez la
  place sur le support de destination.

**Pourquoi cette pièce existe.** `strings` est lancé sur le PÉRIPHÉRIQUE, pas
sur les fichiers. Il lit donc les octets du volume tels qu'ils sont : ce qui a
été effacé mais dont les blocs n'ont pas été réécrits, le *slack* de fin de
bloc, le swap, les pages libérées d'une base de navigateur. C'est la seule
pièce de la collecte qui répond à « cela a-t-il jamais existé sur ce disque ? »
quand l'historique a été vidé et les fichiers supprimés.

C'est vrai en particulier des **adresses MAC** : une machine du réseau local,
un point d'accès associé une seule fois, une interface qui n'est plus dans
aucune configuration y laissent leur adresse. Une MAC lue ici n'est jamais
mieux qu'« à vérifier » — elle n'a ni date, ni fichier d'origine —, mais c'est
souvent la seule pièce qui garde la trace d'un matériel dont le système ne
parle plus. La synthèse des adresses la rapproche de celles qui, elles, ont
une provenance.

**Ce qu'elle ne dit pas, et il faut le répéter dans le rapport :** ni quand, ni
dans quel fichier, ni par quel compte. Une chaîne n'y est pas datée et n'est
imputable à personne. Elle devient un fait daté seulement si une autre pièce —
un historique, la timeline, un journal — porte la même valeur avec une date.
Quand aucune ne le fait, c'est cela qu'il faut écrire.

**Comment y chercher.** Jamais en l'ouvrant dans un éditeur : il pèse des
gigaoctets. `extraire.py --indicateurs` le lit en flux, par blocs, avec un
chevauchement entre eux pour ne pas manquer une chaîne à cheval. Le fait qu'il
produit porte, lui, le décalage de la première occurrence — compté par
l'extracteur au fil de sa propre lecture, et non repris de `strings`.

**Les limites du procédé.** `strings` ignore les suites de moins de quatre
caractères imprimables : un mot de passe très court, un identifiant bref n'y sont
pas. Le texte encodé en UTF-16 (rare sous Linux, courant dans un document
Office) ne sort pas non plus sans `strings -el`. Et un volume chiffré ne rend
que du bruit : si le `.gz` est anormalement petit ou illisible, c'est le
premier soupçon à vérifier.
