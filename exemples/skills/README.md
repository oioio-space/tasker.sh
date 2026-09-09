# Analyser une collecte — mode d'emploi

`collecte-linux.conf` **prend** les pièces. Le skill posé ici les **lit** et en
tire un rapport. Les deux vivent côte à côte parce qu'ils vont ensemble : le
skill sait exactement ce que la conf a écrit, et où.

| skill | ce qu'il rend |
|---|---|
| `forensic-linux/` | identité et installation de la machine, chronologie de vie attribuée aux comptes, réseau, domaine, navigation, supports amovibles, éléments suspects |
| `conformite-linux/` | les écarts aux règles internes que vous fournissez : comptes et mots de passe, élévation de privilèges, secrets en clair, durcissement, usages |

Les deux lisent la même collecte et se complètent : `forensic-linux` donne les
**dates**, `conformite-linux` les **écarts**. Un manquement daté vaut mieux
qu'un manquement constaté — lancez les deux, et citez les identifiants des deux
fichiers dans le rapport de conformité.

Format **Agent Skills** (`SKILL.md`), lu tel quel par Claude Code et par Crush.

---

## 1 · Ce qu'il faut installer

**`python3` et sa bibliothèque standard. Rien d'autre.**

Pas de `pip`, pas de MCP, pas de réseau. Le module `sqlite3` livré avec Python
lit les historiques Firefox et Chrome. Le skill fonctionne sur une machine
coupée d'Internet — c'est même pour ça qu'il embarque `references/artefacts.md`,
qui explique ce qu'est chaque pièce : le modèle ne peut aller le chercher
nulle part.

## 2 · Poser le skill

Pour Crush, une fois pour toutes :

    mkdir -p ~/.config/crush/skills
    cp -r exemples/skills/forensic-linux exemples/skills/conformite-linux \
          ~/.config/crush/skills/

Ou seulement pour un dossier de travail — Crush cherche aussi dans
`.crush/skills/`, `.agents/skills/` et `.claude/skills/` du projet courant :

    mkdir -p ~/analyse/.crush/skills
    cp -r exemples/skills/forensic-linux ~/analyse/.crush/skills/

## 3 · Protéger les scellés

**La seule garantie qui tienne est celle du noyau.** Une permission dans un
fichier de configuration se contourne ; un montage en lecture seule, non :

    sudo mount -o bind,ro /mnt/SAN/ANALYSE /mnt/scelles

Travaillez ensuite sur `/mnt/scelles`. Rien — ni le skill, ni un outil mal
réglé, ni un modèle qui dérape — ne pourra écrire dans la collecte.

L'extracteur, lui, ne modifie rien : il lit les archives en flux, sans les
dépaqueter. C'est vérifié à chaque évolution en comparant l'empreinte de
l'arborescence avant et après. Mais ne comptez pas là-dessus : montez en `ro`.

## 4 · S'en servir

### La méthode sûre, en deux temps

Lancez l'extraction **vous-même**, hors de l'agent :

    C=/mnt/scelles/LINUX/PRJ/PC01_B13_SYCOBS_LINUX
    K=~/.config/crush/skills
    python3 $K/forensic-linux/scripts/extraire.py   "$C" -o ~/analyse/faits.jsonl
    python3 $K/conformite-linux/scripts/controles.py "$C" -o ~/analyse/constats.jsonl

Si vos règles sont déjà écrites dans un fichier `.regles`, donnez-le, avec les
faits — ce sont eux qui portent les dates et le fuseau du poste :

    python3 $K/conformite-linux/scripts/controles.py "$C" \
            --regles $K/conformite-linux/references/regles/usage-non-professionnel.regles \
            --faits ~/analyse/faits.jsonl -o ~/analyse/constats.jsonl

Ce fichier s'écrit à la main : une règle par bloc, la phrase de la charte
recopiée, puis les indices à chercher. **Relisez-le contre la charte de
l'entreprise avant de vous en servir** : il n'en est pas la copie.

Puis ouvrez l'agent dans `~/analyse` et demandez-lui le rapport. Il n'a alors
besoin que de **lire** `faits.jsonl` — pas d'exécuter quoi que ce soit.

C'est la méthode à préférer avec une configuration Crush restreinte, du genre :

```json
"permissions": { "allowed_tools": ["view", "ls", "grep"] }
```

Ces trois outils sont en lecture seule, et suffisent. **N'ajoutez pas `bash`
à cette liste pour faire tourner l'extracteur** : ce serait accorder le droit
d'écrire partout, y compris dans les scellés, pour une commande que vous pouvez
lancer à la main.

### Ou d'un seul geste

Si l'agent a le droit d'exécuter des commandes et que les scellés sont montés
en lecture seule :

    /forensic-linux

puis donnez-lui le dossier de collecte — celui qui porte le PREFIX et contient
`SYSTEME/`, `COMPTES/`, `TIMELINE/`…

## 5 · Ce que l'extraction produit

    faits.jsonl              un fait par ligne
    faits-manifeste.json     les empreintes de ce qui a été lu

Un fait :

```json
{"id":"F0012","categorie":"support","fait":"support amovible USB branché",
 "valeur":"port 1-2, idVendor=0781, idProduct=5583",
 "horodatage":"2019-09-02T14:20:07+0200",
 "source":"JOURNAUX/PREFIX_journal.txt",
 "methode":"journalctl -D var/log/journal -o short-iso, puis motifs"}
```

`source` **et** `methode` : de quoi refaire le geste à la main. C'est la règle
qui prime sur tout dans le skill — aucune affirmation sans son origine.

Le manifeste porte le SHA-256 de chaque pièce lue, de l'extracteur et du
fichier de faits.

## 6 · Reproductibilité

Les deux ne se valent pas, et le rapport doit le dire :

- **L'extraction est reproductible à l'octet près.** Même collecte, même
  `faits.jsonl` — mesuré sur trois passages avec `PYTHONHASHSEED` aléatoire.
  L'ordre est fixé, et les dates sont lues **sans dépendre de la langue** du
  poste : `last` et `rpm --last` écrivent « lun. sept. 2 » sur un poste
  français, et l'extracteur les lit aussi bien qu'un « Mon Sep 2 ». Deux
  analystes qui comparent leurs `faits_sha256` doivent trouver la même valeur.
- **Le rapport ne l'est pas** : c'est un texte. Ce qui est stable, c'est sa
  structure — dix sections imposées — et ses appuis : chaque affirmation
  renvoie à un identifiant `F0123`. On ne relit pas la prose, on rejoue les
  faits.

## 7 · Si la collecte est grosse

Un `faits.jsonl` de plusieurs dizaines de milliers de lignes ne tient pas dans
une fenêtre de contexte. Découpez par catégorie plutôt que tout charger :

    grep '"categorie":"evenement"'      faits.jsonl > evenements.jsonl
    grep '"categorie":"suspect"'        faits.jsonl > suspects.jsonl
    grep '"categorie":"telechargement"' faits.jsonl > telechargements.jsonl

Les catégories : `machine`, `compte`, `domaine`, `evenement`, `support`,
`reseau`, `navigation`, `telechargement`, `usage`, `persistance`, `suspect`,
`paquet`, `timeline`, `recuperation`, `limite`.

### Les sous-agents de Crush

Au-delà, Crush sait répartir : l'outil **`agent`** lance des sous-agents **en
parallèle**, et — c'est le point qui compte ici — le code les restreint aux
outils de **lecture seule** : `view`, `ls`, `grep`, `glob`, `sourcegraph`,
`lsp_*`. Un sous-agent **ne peut pas écrire**, par construction, quelles que
soient les permissions du parent.

Pour l'activer, ajoutez-le à vos permissions :

```json
"permissions": { "allowed_tools": ["view", "ls", "grep", "glob", "agent"] }
```

`agent` n'est pas `bash` : il n'accorde aucun droit d'exécution. Il reste donc
compatible avec la règle du §4 — l'extraction se lance à la main, l'agent ne
fait que lire.

Le sous-agent emploie par défaut le modèle **large**. Si vous voulez lui
donner le petit, pour aller vite sur du résumé :

```json
"agents": { "task": { "model": "small" } }
```

Le skill dit quoi leur demander, et surtout ce qu'ils ne doivent pas faire :
lire et résumer, jamais conclure ni qualifier.

### Suivre une analyse longue

Crush expose aussi **`todos`**. Le skill s'en sert pour poser les dix sections
du rapport avant de commencer : une analyse s'interrompt, la liste dit où on en
était. À ajouter aux permissions si vous le voulez.

## 8 · Vérifier l'extracteur

Sur un poste neuf, avant de s'en servir sur une vraie affaire :

    python3 -m py_compile forensic-linux/scripts/extraire.py
    python3 forensic-linux/scripts/extraire.py --help

Puis sur une collecte connue, deux fois de suite :

    python3 … -o /tmp/a.jsonl && python3 … -o /tmp/b.jsonl && cmp /tmp/a.jsonl /tmp/b.jsonl

Les deux doivent être identiques. S'ils diffèrent, quelque chose a bougé dans
la collecte entre les deux lectures — c'est un fait en soi, et grave.

---

## Le skill de conformité, en deux mots

Il ne juge rien sans règle écrite. Le script relève des **constats** — « clé
privée SSH sans phrase de passe », « `PermitRootLogin yes` » — chacun
accompagné de la **question** à laquelle une règle devra répondre pour en faire
un manquement. Le rapprochement est le travail du rapport, et le skill impose
de le **montrer** : un tableau « règle → contrôle retenu » avant tout résultat,
pour qu'un lecteur puisse contester la méthode avant les conclusions.

Trois choses qu'il refuse de faire, et qui font sa valeur :

- **inventer une règle** parce qu'un constat paraît grave — ce qui n'est pas
  couvert va dans « observations sans règle correspondante » ;
- **élargir une règle** — « les supports amovibles doivent être chiffrés » ne
  dit pas « les supports amovibles sont interdits » ;
- **confondre une visite et un transfert** — un service de stockage personnel
  dans l'historique établit une consultation, jamais qu'un fichier est parti.

Le champ `portee` distingue ce qui vise un **compte** de ce qui vise le
**poste** : imputer à un agent un `sudo NOPASSWD` posé par le service
informatique est la faute la plus facile à commettre ici.

Sans règles fournies, le skill rend un **état des lieux** et dit qu'aucun
manquement n'y est établi. `references/regles-type.md` sert alors à comparer
avec la charte quand elle arrive — et à repérer ce qu'elle omet.

## Écrire un autre skill à côté

La collecte servira à d'autres analyses — conformité à une charte, comparaison
entre postes. Ils se posent ici, dans un dossier voisin, et gagnent à suivre
les mêmes règles :

1. **Un extracteur déterministe d'abord, le modèle ensuite.** Le modèle
   recoupe et rédige ; il ne fouille pas les fichiers. C'est plus sûr avec un
   modèle local, et c'est ce qui rend le résultat vérifiable.
2. **Chaque fait porte sa source et son geste.** Sans quoi le rapport n'est
   qu'une opinion bien tournée.
3. **Le skill dit ce qu'il ne faut pas faire**, pas seulement ce qu'il faut :
   ne pas combler un trou par une déduction, ne pas attribuer à une personne ce
   qu'un compte a fait, ne pas inventer le sens d'un artefact.
4. **Hors ligne, tout ce qui compte est dans le skill.** Un format de date, une
   table SQLite, un piège : s'il n'est pas écrit dans `references/`, il
   n'existe pas.
