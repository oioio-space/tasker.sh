---
name: forensic-linux
description: Analyse une collecte produite par tasker.sh exemples/collecte-linux.conf et rédige un rapport forensique daté et sourcé — identité et installation de la machine, chronologie de vie attribuée aux comptes, réseau (IP, MAC, DNS, domaine), navigation et téléchargements, supports amovibles, comptes locaux et de domaine, contrôleurs de domaine, éléments suspects. À utiliser dès qu'un dossier de collecte Linux doit être exploité, ou quand on demande « que s'est-il passé sur ce poste ». Chaque fait rapporté cite son fichier source et la commande qui l'a obtenu.
user-invocable: true
license: MIT
compatibility: "Exige python3 (bibliothèque standard seule, dont sqlite3) et une collecte produite par tasker.sh exemples/collecte-linux.conf. Installez aussi ripgrep sur le poste d'analyse : sans lui, l'outil grep de l'agent se rabat sur un parcours qui ignore son propre délai de garde et ne rend jamais la main sur une grosse collecte. Fonctionne entièrement hors ligne."
---

# Analyse d'une collecte Linux

Vous exploitez un dossier produit par `collecte-linux.conf`. Votre livrable est
un **rapport en français**, adossé à un fichier de faits bruts.

## Règle qui prime sur tout

**Aucune affirmation sans sa source.** Chaque fait du rapport porte le fichier
d'où il vient et le geste qui l'a obtenu, de sorte qu'un lecteur puisse le
refaire à la main. Un fait dont vous ne pouvez pas dire l'origine ne va pas
dans le rapport : il va dans « ce que la collecte ne dit pas ».

Vous ne modifiez jamais la collecte. Vous n'y écrivez rien, vous n'y dépaquetez
rien : les archives se lisent en flux.

## Marche à suivre

### 1 · Extraire les faits

```bash
python3 scripts/extraire.py <dossier PREFIX/> -o faits.jsonl
```

Il ne demande que `python3` et sa bibliothèque standard, lit les archives sans
les extraire, et écrit un fait par ligne :

```json
{"id":"F0012","categorie":"support","fait":"support amovible USB branché",
 "valeur":"port 1-2, idVendor=0781, idProduct=5583","horodatage":"2019-09-02T14:20:07+0200",
 "source":"JOURNAUX/PREFIX_journal.txt","methode":"journalctl -D var/log/journal -o short-iso, puis motifs"}
```

Trois champs ne se devinent pas — les ignorer fait dire au rapport le contraire
de la pièce :

| champ | à lire comme |
|---|---|
| `provenance` | la pièce est un dossier de récupération (`STRINGS/`, `PHOTOREC/`, `SUPPRIMES/`) : des **octets**, pas des fichiers. Ni date, ni compte — ne fonde jamais « le compte a fait ceci » |
| `trouve: false` | fait d'**absence** : la valeur est ce qu'on a cherché SANS le trouver. La lire comme une trouvaille est le pire contresens possible ici |
| un `…` final | valeur **coupée** : ne la citez pas comme une phrase entière, et ne lisez pas une adresse collée au `…` — elle est peut-être tranchée |

Il écrit aussi `faits-manifeste.json` : l'empreinte SHA-256 de chaque pièce lue,
de l'extracteur et des listes de recherche — **quels octets**, **par quel
outil**, **pour quelles questions**.

Les historiques de navigation ne sont **pas bornés** : pages, téléchargements,
marque-pages, recherches, saisies de formulaire — tout ce que la base porte
devient un fait. Une borne aurait jeté les entrées les plus ANCIENNES, seules à
survivre quand l'historique récent a été vidé. Attendez-vous à des dizaines de
milliers de faits `navigation` ; le tableau du rapport, lui, reste réglable par
`--lignes`. Les sites à mot de passe enregistré sont relevés — **le site
seul**, jamais le secret.

Le même contenu sort en `faits.csv`. Si l'on sait déjà ce que l'on cherche —
empreinte, adresse, nom —, `--indicateurs fichier.txt` le cherche dans toute la
collecte : `references/indicateurs.md`.

**Les dates.** Chaque fait porte son horodatage tel que la pièce le donne : en
UTC (suffixe `Z`) quand elle compte en epoch — `wtmp`, navigateurs,
NetworkManager —, avec son décalage quand elle l'écrit (`journalctl`), sans rien
quand elle ne le dit pas (ligne syslog, `dpkg.log` : c'est l'heure du poste). Le
binaire `wtmp` passe avant la sortie texte de `last`, qui porte l'heure du poste
d'ANALYSE. Le brouillon met tout dans le fuseau du poste ; **vous ne convertissez
rien à la main**.

Quatre fiches, à ouvrir **au besoin**, jamais en entier : chacune s'ouvre par
un index donnant le titre exact de ses sections. Lisez la seule qui répond —
`grep -A 60 '<titre>' references/<fiche>`. `artefacts.md` coûte six mille
jetons ; une de ses sections, six cents.

| fiche | à ouvrir quand… |
|---|---|
| `references/artefacts.md` | un nom de fichier ne vous dit pas ce qu'il PROUVE. Hors ligne, c'est la seule source sur le format d'un `places.sqlite` ou les dates Chrome depuis 1601. **N'inventez jamais** la signification d'un artefact absent de cette fiche : dites que vous ne savez pas |
| `references/inventaire.md` | avant d'écrire « on ne sait pas » — la réponse y est peut-être ; et avant d'affirmer, pour vérifier que la pièce dit bien ce que vous lui faites dire |
| `references/ou-chercher.md` | une pièce manque : son chemin d'origine, l'étape à rejouer, et comment distinguer « le système ne l'avait pas » de « la collecte l'a ratée » |
| `references/sources.md` | vous cherchez par quelle COMMANDE une réponse a été obtenue |

### Les pièces qui n'ont ni date ni auteur

Trois sources disent ce qu'il y a **sans dire quand ni par qui** : les chaînes
des disques (`STRINGS/`), ce que photorec et `xfs_undelete` rendent sans nom, et
les motifs repérés seuls (`interet`). Leurs faits portent tous `provenance`.

**La règle vaut pour les trois, sans exception :** le contenu est établi, la
provenance ne l'est pas. « L'adresse figure dans les octets du volume racine »
se dit ; « le compte a visité ce site » ne se dit pas, sauf si une pièce datée
le porte. **Ouvrez la pièce citée avant d'en écrire un mot**, et rayez le reste
en disant pourquoi.

`SUPPRIMES/` n'existe que pour un volume **xfs** ; ailleurs les fichiers rendus
viennent de photorec seul, et un fait le dit. Pour chercher :
`--textes` prend une chaîne par ligne sans syntaxe, `--indicateurs` mêle
empreintes, adresses et expressions — `references/indicateurs.md`.

### Quatre synthèses, et ce qu'elles valent

Quatre tableaux ne lisent aucune pièce : ils relisent les faits établis, chaque
ligne citant les identifiants dont elle sort — **comptes**, **périodes sans
trace**, **supports amovibles**, **adresses réseau**. Ce qu'ils valent et leurs
pièges (série d'un support, IP privée, MAC tirée au hasard) :
`references/artefacts.md`.

Deux phrases à ne JAMAIS écrire, parce qu'elles disent plus que la pièce :

- « ce compte est inutilisé » — il est sans session **dans `wtmp`**, ce qui
  n'est pas la même chose ;
- « le poste n'a pas servi » — écrivez « la collecte ne porte aucune trace
  entre le X et le Y ». Un usage qui n'écrit rien ne laisse rien.

**La super-timeline plaso** est cherchée par son CONTENU, où qu'elle soit et
quel que soit son nom. Elle n'est pas recopiée : elle est LUE. Il en sort ce qui
s'est passé — ce qui a été **branché**, **où il a été**, ce qu'il a **lancé**,
**téléchargé**, **installé** —, un **récit jour par jour**, et le recoupement
avec le reste des faits : `role` = `corroboration` marque ce que **deux sources
indépendantes** portent, `corroboration-seul` ce que plaso est seul à porter
— la pièce d'origine a pu être vidée. Détail :
`grep -A 60 'super-timeline' references/artefacts.md`.

**Si l'extraction plante, relancez la même commande** : elle reprend où elle
s'est arrêtée.

**Avant un `grep` sur la collecte**, vérifiez `ripgrep` (`command -v rg`) :
sans lui l'outil ne rend jamais la main sur une grosse pièce. Visez un
sous-dossier, jamais la racine.

### 2 · Vérifier avant d'écrire

Trois contrôles, dans cet ordre. Ils changent la lecture de tout le reste.

1. **Le fuseau.** Le fait « fuseau horaire du poste » donne le fuseau du poste
   analysé. La timeline mactime, elle, a été écrite dans le fuseau passé à
   `TZ_MACTIME` lors de la collecte — souvent UTC. Dites dans le rapport dans
   quel fuseau vous écrivez, et convertissez tout dans celui-là.
2. **L'horloge matérielle.** Si le fait « horloge matérielle » vaut « heure
   locale », les dates du noyau au démarrage peuvent être décalées : signalez-le.
3. **Les trous.** Comparez la première et la dernière date de chaque source.
   Un `wtmp` qui commence trois jours avant l'arrêt ne prouve pas que la machine
   n'a servi que trois jours — il prouve que le fichier a été tourné. Dites-le.
4. **Ce qui manque.** L'extraction pose un fait `limite` par pièce absente, avec
   son chemin d'origine et l'étape à rejouer. Lisez-les **avant** de rédiger :
   ils décident de ce que le rapport peut affirmer.

## Quand une pièce manque

Ne vous contentez jamais d'écrire « absent ». Une absence a deux causes : *le
système ne l'avait pas* — un fait sur ce système —, ou *la collecte l'a ratée*,
et il faut y retourner. `references/ou-chercher.md` les distingue pièce par
pièce et dit par quoi chacune a été remplacée. Quand le doute demeure :

1. **Demandez le rapport de la collecte** — `PREFIX_rapport.txt` et
   `PREFIX_script.log` : ils disent, étape par étape, ce qui a réussi, échoué
   ou été passé. **Ils ne sont pas dans le dossier de collecte**, mais là où
   `tasker.sh` a été lancé.
2. **Allez la lire vous-même sur l'image**, si elle est montée à côté de la
   collecte — sous `mnt/` par convention, ou là où l'analyste l'indique. Tout
   ce qui LIT y est permis, `bash` compris : `cat`, `stat`, `strings`, `find`,
   `grep`, `sqlite3`, `tar -t`. Rien n'y est écrit : dirigez vos sorties vers
   le dossier d'analyse. Une pièce lue là **n'a pas d'empreinte au manifeste** —
   citez-la comme venant de l'image, et si elle porte une conclusion,
   recopiez-la dans la collecte et relancez l'extraction.
   `grep -A 40 'lire vous-même' references/ou-chercher.md`.
3. **Demandez la reprise**, en donnant à votre interlocuteur ce qu'il lui faut
   pour agir, pas une plainte :

   > Il manque le journal systemd (`JOURNAUX/PREFIX_journal.txt`). Sur l'image
   > montée, il vit dans `/var/log/journal/<machine-id>/`. L'étape est
   > « Journal systemd, en clair ». Pour la rejouer seule, relevez son numéro
   > avec `-l` puis relancez avec `--only <numéro>`. Si l'image n'est plus
   > montée, remontez-la en lecture seule.

4. **Écrivez le rapport quand même**, avec ce que vous avez — une collecte
   incomplète est le cas courant. Dites en « Les limites » ce que la pièce
   manquante vous empêche de conclure, et ce que vous auriez pu conclure si
   elle avait été là. Un rapport qui attend une pièce ne sert personne ; un
   rapport qui masque ce qu'il ignore est pire.

### 3 · Répartir sur des sous-agents — faites-le, ne l'envisagez pas

**Lancez les sous-agents dès que `faits.jsonl` dépasse quelques centaines de
lignes** : c'est la façon normale de travailler ici, pas une option pour les
grosses collectes. Comptez d'abord, sans rien charger :

```bash
cut -d'"' -f8 faits.jsonl | sort | uniq -c | sort -rn   # faits par catégorie
wc -l faits.jsonl
```

**N'ouvrez jamais `faits.jsonl` en entier « pour voir »** : vous y brûlez la
fenêtre de contexte, et vous n'aurez plus de place pour rédiger.

Puis l'outil `agent`, **un appel par thème, dans un seul message** pour qu'ils
tournent en parallèle. Crush les restreint aux outils de **lecture seule**
(`view`, `grep`, `glob`, `ls`) : un sous-agent ne peut ni écrire dans les
scellés ni lancer une commande.

| sous-agent | son filtre dans `faits.jsonl` |
|---|---|
| machine | `categorie` = `machine`, `reseau`, `adresse` |
| comptes | `compte`, `evenement` |
| navigation | `navigation`, `telechargement`, `usage` |
| **super-timeline** | `role` = `plaso-journee`, `plaso-sujet` |
| **corroboration** | `role` = `corroboration`, `corroboration-seul` |
| supports | `support`, `appareil` |
| suspect | `suspect`, `persistance`, `interet`, `recuperation` |
| limites | `limite` — ce que l'extraction n'a PAS pu lire |

La consigne, la même pour tous, une seule ligne à changer :

> Lis `faits.jsonl` dans le dossier courant. Ne retiens que les lignes dont le
> champ `categorie` vaut `reseau` — utilise `grep`, n'ouvre pas tout le
> fichier. Rends dix lignes au plus, chaque affirmation suivie des
> identifiants qui la portent (`F0123`). Cite les valeurs telles quelles.
> N'invente rien, ne conclus rien, ne qualifie rien de suspect : je recoupe.

**Un sous-agent lit et résume ; il ne conclut pas.** Ses identifiants servent à
le revérifier sans le croire sur parole : le jugement reste à vous. Si l'outil
`agent` manque — `options.disabled_tools` peut le retirer —, dites-le dans le
rapport et lisez par catégorie dans l'ordre du plan.

### 4 · Recouper

C'est ici que vous valez mieux qu'un `grep`. Rapprochez, en nommant les deux
sources à chaque fois :

- une **session** (`wtmp`) et ce qui s'est passé pendant sa fenêtre : sudo,
  branchement USB, navigation, écriture de fichier dans la timeline ;
- un **support amovible** et sa chaîne : branchement, **numéro de série**,
  modèle, `/dev/sdX`, montage — dont le chemin `/run/media/<compte>/` **nomme
  le compte** —, débranchement. **Ce qui a été copié dessus est déjà dans le
  brouillon** : la timeline a été interrogée sous chaque point de montage, un
  `...b` étant une création (donc une copie vers le support) et un `.a..` une
  lecture ; aucune ligne veut dire que le support n'a pas été lu, pas qu'il n'a
  rien reçu. Sans environnement graphique, pas de `/run/media/` : l'attribution
  passe par la session ouverte à cet instant — un rapprochement, pas une
  preuve, et dites-le ;
- un **téléchargement** et le fichier dans la timeline — déjà fait, par un
  fait `confirme: F0123`. Lisez le libellé : « fichier retrouvé » vaut **au
  chemin annoncé** ; « fichier de MÊME NOM » n'est qu'une homonymie, sans
  acteur. Un fichier non retrouvé se dit aussi ;
- une **adresse IP** vue dans un `Accepted password … from` et les comptes qui
  s'en servent ;
- un **compte de domaine** du cache sss et une session à son nom ;
- un **domaine ayant posé un cookie** mais absent de l'historique : les deux
  bases sont indépendantes, et vider l'historique ne touche pas aux cookies.
  Le signaler quand le cas se présente — c'est une visite dont la trace
  d'historique a disparu.

Quand un rapprochement tient à la seconde près, dites-le. Quand il tient à
l'heure près, dites-le aussi — la précision fait partie du fait.

### 5 · Rédiger

Ne partez pas d'une page blanche. Faites d'abord produire le brouillon :

```bash
python3 scripts/brouillon.py faits.jsonl -o rapport-forensic-<PREFIX>.md
```

Il contient les **sections dans l'ordre** (celui du plan ci-dessous), tous les
tableaux déjà remplis depuis les faits, une demande de reprise toute prête, une
annexe, un lexique — et des passages marqués **« À rédiger »** qui disent ce
qu'il faut écrire à cet endroit. Toutes les dates y sont dans le fuseau du
poste.

Chaque ligne d'événement répond à **quand, qui, quoi, où, comment** : la date,
le compte, le fait, le terminal ou l'origine ou le chemin, la pièce et le
geste. Les événements sont rangés par **session** — ce qui arrive pendant
qu'un compte est ouvert lui est rapproché. Quand deux sessions se chevauchent,
la ligne dit « ? (session simultanée) » : **ne l'attribuez à personne** sans
une autre trace (le chemin `/run/media/<compte>/`, le compte d'un sudo).

Le brouillon s'ouvre sur **« En bref »** : cinq phrases sans jargon pour qui ne
lira que cela. Un rapport se lit par quelqu'un qui n'est pas du métier et se
vérifie par quelqu'un qui l'est — les phrases sont pour le premier, les
identifiants et les tableaux pour le second.

Ce que vous faites du brouillon :

- **vous écrivez la prose** aux endroits marqués, et vous retirez la marque ;
- **vous élaguez les tableaux** — la chronologie surtout — en disant ce que
  vous retirez et pourquoi ;
- **vous ne réécrivez jamais une cellule.** Une date, une valeur, un
  identifiant viennent du fichier de faits ; les retaper de mémoire est la
  façon la plus sûre d'introduire une erreur qu'aucun lecteur ne détectera.
  S'il manque une colonne, demandez-la au script, ne la remplissez pas à la
  main.

Le rapport suit cet ordre, en français, à l'indicatif, sans jargon inutile :

1. **La machine** — nom, système, version, machine-id, fuseau, installation,
   dernier arrêt. Un tableau court suffit.
2. **Les comptes** — locaux et de domaine, séparés, avec ce qui distingue un
   compte qui a servi d'un compte qui existe. Nommez les comptes : ce sont des
   identités numériques, pas des personnes, et le rapport le précise une fois.
3. **Le domaine** — royaume, contrôleurs, annuaire, appartenance prouvée ou non.
4. **Le réseau** — interfaces, MAC, IP, DNS, passerelle, réseaux sans fil
   enregistrés, hôtes SSH contactés. Puis la **synthèse des adresses** : une
   ligne par IP, par MAC et par hôte web, avec la provenance de chacune.
5. **La chronologie de la machine** — un tableau daté, du plus ancien au plus
   récent : installation, démarrages, sessions, sudo, USB, navigation,
   téléchargements, arrêt. Une colonne « compte », une colonne « source ».
   C'est le cœur du rapport ; ne le noyez pas, gardez les événements qui
   éclairent la vie de la machine.
6. **La navigation et les téléchargements** — par compte, avec les dates.
7. **Les supports amovibles** — modèle, port, montage, et ce qui a été lu ou
   écrit dessus.
8. **Ce qui attire l'œil** — un tableau : le constat, pourquoi c'est notable,
   la source, et **ce qu'il faudrait vérifier pour trancher**. N'affirmez pas
   une compromission : montrez ce qui la rendrait vraie ou fausse.
9. **Les limites** — ce que la collecte ne contient pas, les trous de journaux,
   les dates douteuses, les étapes rouges du journal de collecte.
10. **Annexe : méthode** — la commande d'extraction, le nombre de faits, les
    empreintes recopiées de `faits-manifeste.json` (extracteur, fichier de
    faits, et les pièces citées dans le rapport), et la table `id → source`.

## Écrire un rapport plus long que ce que le modèle peut sortir d'un coup

Un rapport complet dépasse souvent la limite de sortie d'un modèle. Le
brouillon est déjà sur disque : **remplacez un passage « À rédiger » à la
fois**, par l'outil d'édition, sans jamais réécrire le fichier entier — les dix
sections sont indépendantes, c'est fait pour. Posez-les dans l'outil de suivi
de tâches s'il y en a un (Crush a `todos`) : une analyse longue s'interrompt.

## Reproductibilité

Distinguez les deux, et dites-le dans l'annexe :

- **L'extraction est reproductible à l'octet près.** Même collecte, même
  extracteur, même `faits.jsonl` : l'ordre est fixé, les dates ne dépendent pas
  de la langue du poste, rien n'est daté de l'exécution. Le manifeste, lui,
  porte la date du jour — il décrit l'exécution, pas les pièces. Deux analystes
  qui comparent leurs `faits_sha256` doivent trouver la même valeur ; sinon, la
  collecte a bougé.
- **Le rapport ne l'est pas** : c'est un texte. Ce qui doit être stable, c'est
  sa **structure** — les dix sections, dans cet ordre — et ses **appuis** :
  chaque affirmation renvoie à un `F0123`, donc à une ligne vérifiable. Un
  lecteur ne relit pas votre prose, il rejoue vos faits.

## Ce qu'il ne faut pas faire

- **Ne comblez pas un trou par une déduction.** « Aucune session entre le 3 et
  le 8 » ne veut pas dire « personne n'a utilisé la machine » : `wtmp` peut
  avoir été tourné, ou effacé. Écrivez ce que vous voyez, et ce que ça exclut.
- **N'attribuez pas une action à une personne.** Un compte a agi. Qui tenait le
  clavier est une question que la collecte ne tranche pas — dites-le une fois et
  tenez-vous-y.
- **Ne classez pas « suspect » ce qui est banal.** `sudo yum install` un mardi
  matin n'est pas une intrusion. Gardez le mot pour ce qui le mérite, et
  justifiez-le chaque fois.
- **Ne datez jamais une commande d'un historique non daté.** L'extraction
  distingue les deux : dans le second cas, la position d'une ligne ne prouve
  rien de son moment. Recoupez avec une session ou une trace datée, ou dites
  que la date est inconnue.
- **Ne masquez pas votre incertitude.** Le champ `confiance` vaut `certaine`,
  `forte` ou `à vérifier` : reportez-le. Un fait à vérifier signalé comme tel
  vaut mieux qu'une certitude fausse.
- **N'inventez pas de chemin ni de commande.** Si vous n'avez pas lu le
  fichier, vous ne le citez pas.
