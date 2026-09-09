---
name: forensic-linux
description: Analyse une collecte produite par tasker.sh exemples/collecte-linux.conf et rédige un rapport forensique daté et sourcé — identité et installation de la machine, chronologie de vie attribuée aux comptes, réseau (IP, MAC, DNS, domaine), navigation et téléchargements, supports amovibles, comptes locaux et de domaine, contrôleurs de domaine, éléments suspects. À utiliser dès qu'un dossier de collecte Linux doit être exploité, ou quand on demande « que s'est-il passé sur ce poste ». Chaque fait rapporté cite son fichier source et la commande qui l'a obtenu.
user-invocable: true
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

Le script ne demande que `python3` et sa bibliothèque standard. Il lit les
archives sans les extraire et écrit un fait par ligne :

```json
{"id":"F0012","categorie":"support","fait":"support amovible USB branché",
 "valeur":"port 1-2, idVendor=0781, idProduct=5583","horodatage":"2019-09-02T14:20:07+0200",
 "source":"JOURNAUX/PREFIX_journal.txt","methode":"journalctl -D var/log/journal -o short-iso, puis motifs"}
```

Il écrit aussi `faits-manifeste.json` : l'empreinte SHA-256 de chaque pièce
lue, celle de l'extracteur, celle du fichier de faits. C'est ce qui prouve
**quels octets** ont été analysés.

Deux fiches à lire, dans cet ordre :

- `references/artefacts.md` — **ce que sont** les pièces. Vous travaillez hors
  ligne : ce fichier est la seule source sur le format d'un `places.sqlite`, la
  raison pour laquelle un `.bash_history` n'est pas daté, ou la conversion des
  dates Chrome depuis 1601. **Lisez-le dès qu'un nom de fichier ne vous dit pas
  immédiatement ce qu'il prouve** — et n'inventez jamais la signification d'un
  artefact que vous n'y trouvez pas : dites que vous ne savez pas.
- `references/inventaire.md` — **question par question** : la trace, la pièce
  qui la porte, si elle est lue, et ce qui manque. À consulter avant d'écrire
  « on ne sait pas » : la réponse y est peut-être. Et avant d'affirmer, pour
  vérifier que la pièce dit bien ce que vous lui faites dire.
- `references/sources.md` — **où** chaque réponse se trouve, et ce qu'aucune
  pièce ne dit.

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

### 3 · Recouper

C'est ici que vous valez mieux qu'un `grep`. Rapprochez, en nommant les deux
sources à chaque fois :

- une **session** (`wtmp`) et ce qui s'est passé pendant sa fenêtre : sudo,
  branchement USB, navigation, écriture de fichier dans la timeline ;
- un **support amovible** et sa chaîne complète : branchement, **numéro de
  série**, modèle, `/dev/sdX` obtenu, montage — dont le chemin
  `/run/media/<compte>/` **nomme le compte** —, puis débranchement. Entre les
  deux, les fichiers apparus ou lus sous ce chemin (timeline,
  `recently-used.xbel`) : c'est ainsi qu'on montre une copie. Sans
  environnement graphique il n'y a pas de `/run/media/` : l'attribution passe
  alors par la session ouverte à cet instant, et c'est un rapprochement, pas
  une preuve — dites-le ;
- un **téléchargement** et l'apparition du fichier dans la timeline ;
- une **adresse IP** vue dans un `Accepted password ... from` et les comptes
  qui s'en servent ;
- un **compte de domaine** trouvé dans le cache sss et une session à son nom ;
- un **domaine ayant posé un cookie** mais absent de l'historique : les deux
  bases sont indépendantes, et vider l'historique ne touche pas aux cookies.
  Le signaler quand le cas se présente — c'est une visite dont la trace
  d'historique a disparu.

Quand un rapprochement tient à la seconde près, dites-le. Quand il tient à
l'heure près, dites-le aussi — la précision fait partie du fait.

### 4 · Rédiger

Écrivez `rapport-forensic-<PREFIX>.md` dans cet ordre, en français, à
l'indicatif, sans jargon inutile :

1. **La machine** — nom, système, version, machine-id, fuseau, installation,
   dernier arrêt. Un tableau court suffit.
2. **Les comptes** — locaux et de domaine, séparés, avec ce qui distingue un
   compte qui a servi d'un compte qui existe. Nommez les comptes : ce sont des
   identités numériques, pas des personnes, et le rapport le précise une fois.
3. **Le domaine** — royaume, contrôleurs, annuaire, appartenance prouvée ou non.
4. **Le réseau** — interfaces, MAC, IP, DNS, passerelle, réseaux sans fil
   enregistrés, hôtes SSH contactés.
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

## Reproductibilité

Distinguez les deux, et dites-le dans l'annexe :

- **L'extraction est reproductible à l'octet près.** Même collecte, même
  extracteur, même `faits.jsonl` — l'ordre est fixé, les dates sont lues sans
  dépendre de la langue du poste, rien n'est daté de l'exécution. Le manifeste,
  lui, porte la date du jour : il décrit l'exécution, pas les pièces. Deux
  analystes qui comparent leurs `faits_sha256` doivent trouver la même valeur ;
  s'ils ne la trouvent pas, la collecte a bougé.
- **Le rapport ne l'est pas** : c'est un texte, il variera d'une rédaction à
  l'autre. Ce qui doit être stable, c'est sa **structure** — les dix sections
  ci-dessus, dans cet ordre — et ses **appuis** : chaque affirmation renvoie à
  un identifiant `F0123`, donc à une ligne vérifiable. Un lecteur ne relit pas
  votre prose, il rejoue vos faits.

## Ce qu'il ne faut pas faire

- **Ne comblez pas un trou par une déduction.** « Aucune session entre le 3 et
  le 8 » ne veut pas dire « personne n'a utilisé la machine » : `wtmp` peut
  avoir été tourné, ou effacé. Écrivez ce que vous voyez, et ce que ça exclut.
- **N'attribuez pas une action à une personne.** Un compte a agi. Qui tenait le
  clavier est une question que la collecte ne tranche pas — dites-le une fois
  et tenez-vous-y.
- **Ne classez pas « suspect » ce qui est banal.** `sudo yum install` un mardi
  matin n'est pas une intrusion. Gardez ce mot pour ce qui le mérite, et
  justifiez-le à chaque emploi.
- **Ne datez jamais une commande d'un historique non daté.** L'extraction
  distingue « historique daté » de « historique NON daté » : dans le second
  cas, la position d'une ligne dans le fichier ne prouve rien de son moment.
  Recoupez avec une session ou une trace datée, ou dites que la date est
  inconnue.
- **Ne masquez pas votre incertitude.** Le champ `confiance` vaut `certaine`,
  `forte` ou `à vérifier` : reportez-le. Un fait à vérifier signalé comme tel
  vaut mieux qu'une certitude fausse.
- **N'inventez pas de chemin ni de commande.** Si vous n'avez pas lu le
  fichier, vous ne le citez pas.

## Si la collecte est incomplète

C'est le cas courant. Une étape rouge dans `PREFIX_rapport.txt` explique
souvent un manque : lisez-le et citez-le. Une image sans journal systemd, sans
`wtmp` ou sans profil de navigateur donne un rapport plus court — pas un
rapport qui invente. Dites dans « Les limites » ce que vous auriez pu conclure
si la pièce avait été là.
