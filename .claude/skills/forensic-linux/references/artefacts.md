# Ce que sont les artefacts

À lire quand un nom de fichier ne vous dit rien. Vous travaillez **hors ligne** :
rien de ce qui suit ne peut être cherché ailleurs, tout ce qui compte est ici.

Pour chaque pièce : ce que c'est, ce qu'elle **prouve**, ce qu'elle **ne prouve
pas**, et le piège qui fait dire des bêtises.

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

### `PREFIX_historique.tar.gz`
Les journaux du gestionnaire de paquets : `yum.log`, `dnf.log`,
`history.sqlite`, `dpkg.log`, `apt/history.log`.

- **Ce que `rpm -qa` ne dit pas** : un paquet installé **puis retiré**. Ces
  journaux gardent la trace des suppressions (`Erased:`, `remove`).
