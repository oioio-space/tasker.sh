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

**`python3` et sa bibliothèque standard** pour les scripts — pas de `pip`, pas
de MCP, pas de réseau. Le module `sqlite3` livré avec Python lit les
historiques Firefox et Chrome.

**`ripgrep` pour l'agent**, et celui-là n'est pas optionnel : sans lui, l'outil
`grep` de Crush se bloque sans rendre la main sur une grosse collecte (§2).

Tout fonctionne ensuite coupé d'Internet — c'est même pour ça que le skill
embarque `references/artefacts.md`, qui explique ce qu'est chaque pièce : le
modèle ne peut aller le chercher nulle part.

## 2 · Poser le skill

### Où Crush cherche vraiment

Inutile de deviner, Crush le dit lui-même :

    crush dirs        # première ligne : la configuration ; seconde : l'état

| dossier | ce que c'est | ce qu'on y met |
|---|---|---|
| `~/.config/crush/` | la **configuration** — `crushrc`, `crush.json`, `skills/` | vos fichiers |
| `~/.local/share/crush/` | l'**état** : sessions, cache, et un `crush.json` qu'il écrit seul | rien à la main |

**Deux pièges, et le second coûte des heures.** Un skill posé dans le dossier
d'état n'est jamais trouvé. Et le `crush.json` qui s'y trouve est bien **lu
comme de la configuration**, après celui de `~/.config/` — donc il **prime sur
lui**. Un réglage qui semble ignoré vient presque toujours de là. N'y écrivez
pas pour autant : Crush le réécrit seul, changer de modèle par `ctrl+l` y
laisse une trace. L'ordre, du plus faible au plus fort — la DERNIÈRE ligne est
la plus forte de toutes, et elle est facile à manquer : un `crush.json` posé
dans le dossier d'analyse écrase tout le reste (`internal/config/load.go:58,66`,
« *Load workspace config last so it has highest priority* ) :

    config système → ~/.config/crush/crush.json → ~/.config/crush/crushrc
                   → ~/.local/share/crush/crush.json → configs du projet
                   → <data_directory>/crush.json

Pour les skills, quatre dossiers sont regardés d'office — le premier venu
suffit, **rien à déclarer** :

    ~/.config/crush/skills/     ~/.agents/skills/
    ~/.config/agents/skills/    ~/.claude/skills/

et dans le dossier courant `.crush/skills/`, `.agents/skills/`,
`.claude/skills/`, `.cursor/skills/` — ainsi qu'à la **racine du dépôt git**,
s'il y en a un : un jeu de skills posé là sert tous les sous-dossiers.

Deux variables déplacent tout : `XDG_CONFIG_HOME` remplace `~/.config`, et
`CRUSH_SKILLS_DIR` **remplace les quatre dossiers d'un coup**.

### Une dépendance à ne pas oublier : ripgrep

    command -v rg || sudo apt install ripgrep     # ou dnf/pacman/zypper

Ce n'est pas un confort. L'outil `grep` de Crush appelle `rg` quand il le
trouve, et se rabat sinon sur un parcours en Go appelé **sans le contexte**
(`internal/agent/tools/grep.go:197`) : le délai de garde de cinq secondes posé
juste au-dessus ne peut donc pas l'interrompre. Sur une collecte forensique, ce
parcours lit chaque fichier texte ligne à ligne et **l'interface reste sur
« Waiting for tool response… » sans jamais rendre la main**.

Aucune permission n'est en cause — `grep` n'en réclame aucune, il n'y a donc
pas d'« allow » à donner. Si ça arrive : `esc` annule. Prenez `rg` **avant** de
couper le réseau, et restreignez une recherche à un sous-dossier plutôt qu'à la
racine de la collecte.

### Poser les skills

Pour Crush, une fois pour toutes :

    K="${CRUSH_SKILLS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/crush/skills}"
    C="${XDG_CONFIG_HOME:-$HOME/.config}/crush"
    mkdir -p "$K" "$C"
    # --exclude : un « cp -r » embarque les __pycache__ du dépôt, qui sont des
    # .pyc compilés pour UNE version de Python et n'ont rien à faire dans une
    # copie posée.
    tar -c --exclude=__pycache__ -C exemples/skills forensic-linux conformite-linux \
        | tar -x -C "$K/"
    cp exemples/skills/garde-scelles.sh "$C/" && chmod +x "$C/garde-scelles.sh"
    cp exemples/skills/crushrc    "$C/crushrc"             # puis adaptez base_url

Ou seulement pour un dossier de travail — c'est le plus simple si vous voulez
un jeu de skills par affaire :

    mkdir -p ~/analyse/.crush/skills
    cp -r exemples/skills/forensic-linux ~/analyse/.crush/skills/

Dans les deux cas, Crush doit voir les deux skills. Il n'existe pas de
sous-commande `crush skills` pour le demander ; la façon sûre de le vérifier,
**et elle marche hors ligne** — la découverte est journalisée avant tout appel
au modèle :

    crush run "x" --debug 2>/dev/null
    grep -o '"Successfully loaded skill","name":"[a-z-]*"' \
        "$(crush dirs | sed -n 2p)/logs/crush.log" | sort -u

Les deux noms doivent sortir. Sinon c'est le chemin, pas le skill.

### Ce que le format garantit, et ce qu'il coûte en contexte

Les deux skills suivent le standard ouvert [Agent Skills](https://agentskills.io),
celui que Crush revendique : `name` en minuscules égal au nom du dossier,
`description` sous 1024 **octets** et corps du `SKILL.md` sous 5 000 jetons et
500 lignes — **comptés en octets** dans les deux cas, un accent en valant deux,
ce qui fait qu'un texte français franchit la borne environ 3 % plus tôt qu'on
ne le croit, `scripts/` et
`references/` en chemins relatifs d'un seul niveau, `compatibility` déclaré.
**Ces bornes sont vérifiées par `tests/artefacts.py`** plutôt que recopiées
ici, où elles rouilleraient.

Elles comptent, parce que Crush ne charge pas un skill d'un bloc — c'est la
**divulgation progressive**, en trois temps :

1. **au démarrage** : seuls `name`, `description` et le *chemin* du `SKILL.md`
   entrent dans l'invite. Pour les deux skills du projet, ≈ 404 jetons —
   mais Crush ajoute d'office trois skills embarqués (`crush-config`,
   `crush-hooks`, `jq`), ce qui porte le total réel à **≈ 700**. Ils ne
   partent qu'avec `option disable-skill <nom>` ;
2. **à l'activation** : le modèle lit le `SKILL.md` — d'où la borne des 5 000
   jetons, et d'où son besoin de l'outil `view` ;
3. **à la demande** seulement : les fichiers de `references/`.

C'est pourquoi `artefacts.md` peut peser 5 500 jetons sans gêner. Si vous
ajoutez un skill, gardez la discipline : le `SKILL.md` mince, le détail dans
`references/`. Le standard fournit un validateur — `skills-ref validate
./mon-skill` —, à récupérer avant de couper le réseau.

### Deux formats, un seul à préférer

Le README de Crush est net : « What about the old JSON format? It's still
supported, but it should be considered deprecated. » Le format courant est le
**`crushrc`** — du Bash avec quelques builtins (`provider add`, `model large`,
`permissions allow`, `hook add`, `option`), cherché dans `./.crushrc`,
`./crushrc`, puis `~/.config/crush/crushrc`. Les deux fichiers sont fournis et
font la même chose ; préférez le `crushrc`, gardez le `crush.json` si votre
version de Crush est ancienne.

**N'en posez qu'UN.** S'ils cohabitent, Crush lit les deux et fusionne, le
`crushrc` l'emportant. Il émet bien un avertissement (`load.go:1023`) — mais
**personne ne le voit jamais** : `internal/cmd/root.go:195` pose
`slog.DiscardHandler` avant le chargement de la configuration. Vérifié : stderr
vide, rien dans le journal. Un réglage que vous croyez avoir changé dans le
JSON peut donc être silencieusement recouvert.

Et les listes fusionnent **par ajout** : un `crush.json` déposé dans le dossier
d'analyse peut ainsi **élargir** `allowed_tools`. Il ne peut en revanche ni la
restreindre, ni effacer le hook — testé.

Ce n'est pas qu'une question de mode : un `crushrc` est un shell, donc `$HOME`
et `XDG_CONFIG_HOME` y sont **réellement développés, partout**. En
`crush.json`, le `~` n'est développé que dans certains champs — et il fallait
lire le code de Crush pour savoir lesquels :

| champ de `crush.json` | le `~` marche ? | pourquoi |
|---|---|---|
| `hooks[].command` | **oui** | la commande passe par le shell POSIX embarqué (`shell.Run`) |
| `options.data_directory` | **non** | `SmartJoin` ne teste que `filepath.IsAbs` : Crush crée un dossier nommé `~` |
| `options.skills_paths` | **oui** | `ResolvePaths` passe chaque chemin par `home.Long` (`internal/skills/manager.go:218`), puis résout un `$VAR` |
| `api_key`, `base_url`, `env` | non, mais… | `$VAR`, `${VAR:-defaut}` et `$(cmd)` y sont développés |

Le `crush.json` fourni ne pose donc **aucun chemin absolu, et n'a rien à
éditer de ce côté**. Il en portait deux, et c'était un défaut : livré tel quel,
il créait un `/home/analyste/` sur la machine et y mettait la base et les
journaux. `skills_paths` en est parti pour une autre raison — il est **inutile** :
Crush ajoute d'office `~/.config/crush/skills` et trois autres dossiers globaux
(`internal/config/load.go:607-612`). Quant à `data_directory`, il n'est qu'un
confort : sans lui, la base va dans `~/.local/share/crush`, qui n'est jamais
dans les scellés. Pour la ranger à côté de l'analyse, ajoutez-le **avec votre
chemin absolu** — c'est le seul champ des trois où le `~` ne passe pas.

Dans les deux cas, c'est **du code exécuté au lancement** : un `crushrc` est un
shell complet, et tout `$(...)` d'un `crush.json` s'exécute au chargement. Ne
lancez pas Crush dans un dossier dont vous n'avez pas lu la configuration.

`garde-scelles.sh` est la ceinture décrite au §3 ; le §9 explique les réglages
du modèle.

### Tout dans le dossier d'analyse, rien de global

Le `crushrc` ci-dessus se pose dans `~/.config/crush/`, donc pour TOUS les
projets. On peut aussi ne rien mettre de global : Crush cherche `.crushrc` puis
`crushrc` dans le dossier de travail — en remontant jusqu'à la racine git —, et
**les configurations de projet priment sur les globales** (`load.go:928-955`).
Un poste qui sert aussi à autre chose garde alors son Crush intact.

    ~/analyse/
      .crushrc              ← la configuration ET le hook
      garde-scelles.sh      ← la garde
      .crush/skills/        ← les deux skills (.agents/, .claude/, .cursor/ marchent aussi)
      .crush/               ← l'état de session (data-directory)
      PC01_B13_SYCOBS_LINUX/  ← le scellé
      mnt/                  ← l'image montée en lecture seule

Deux lignes du `crushrc` livré changent, et une disparaît :

    CONFIG="$PWD"                             # au lieu de ~/.config/crush
    option data-directory "$PWD/.crush"
    # option skill-path : à supprimer — .crush/skills est déjà regardé

`$PWD` est le dossier d'où `crush` est lancé : lancez-le depuis le dossier
d'analyse. Depuis un sous-dossier, `.crushrc` serait bien trouvé mais `$PWD`
pointerait ailleurs — donnez alors le chemin absolu.

Vérifié de bout en bout, `~/.config/crush` inexistant : les deux skills sont
chargés, et un `write` d'une pièce neuve dans le scellé est refusé (1 ligne
`"decision":"deny"` au journal, aucun fichier créé).

## 3 · Protéger les scellés

**La seule garantie qui tienne est celle du noyau.** Une permission dans un
fichier de configuration se contourne ; un montage en lecture seule, non :

    sudo mount -o bind,ro /mnt/SAN/ANALYSE /mnt/scelles

Travaillez ensuite sur `/mnt/scelles`. Rien — ni le skill, ni un outil mal
réglé, ni un modèle qui dérape — ne pourra écrire dans la collecte.

L'extracteur, lui, ne modifie rien : il lit les archives en flux, sans les
dépaqueter. C'est vérifié à chaque évolution en comparant l'empreinte de
l'arborescence avant et après. Mais ne comptez pas là-dessus : montez en `ro`.

### Vérifier que la ceinture mord

`garde-scelles.sh` est une ceinture par-dessus le montage : elle a le mérite
d'**expliquer** au modèle pourquoi il ne peut pas écrire, au lieu de le laisser
buter sur un « permission denied ».

**Un scellé s'y reconnaît à sa STRUCTURE, pas à son chemin** : un dossier qui
porte au moins trois des dossiers écrits par `collecte-linux.conf` (`SYSTEME/`,
`COMPTES/`, `JOURNAUX/`…) est une collecte, où qu'il soit posé. Il n'y a donc
rien à déclarer, et surtout aucun chemin à tenir à jour — un chemin écrit en
dur ne protège rien sur un poste où la collecte est ailleurs, tout en ayant
l'air de marcher.

On le vérifie avec un scellé jouet, hors de Crush :

    mkdir -p /tmp/essai/PC01/{SYSTEME,COMPTES,JOURNAUX}
    printf '{"tool_name":"write","tool_input":{"file_path":"/tmp/essai/PC01/SYSTEME/x"},"cwd":"/tmp"}' \
        | ~/.config/crush/garde-scelles.sh ; echo "code $?"

Le script doit écrire son refus et rendre **2**. Un code 0, ou « command not
found », veut dire que la ceinture est absente : le fichier n'est pas là où le
hook le nomme, ou il n'est pas exécutable.

**Ce test ne dit pas que la garde est ARMÉE.** Un hook dont le chemin ne se
résout pas ne bloque rien et ne dit rien : Crush écrit un avertissement dans
son journal, puis laisse passer — et l'écriture aboutit pour de bon. Le script
peut donc rendre 2 tout seul pendant que Crush ne l'appelle jamais. La seule
vérification qui vaille passe par le haut, et elle se lit dans le JOURNAL de
Crush — **pas** sur la sortie de `crush run` : le motif du refus part au modèle,
pas au terminal.

    D="$(crush dirs | sed -n 2p)"          # ou la valeur d'« option data-directory »
    rm -f /tmp/essai/PC01/SYSTEME/x
    crush run "écris bonjour dans /tmp/essai/PC01/SYSTEME/x" >/dev/null 2>&1
    grep -c '"Hook completed".*"decision":"deny"' "$D/logs/crush.log"
    ls /tmp/essai/PC01/SYSTEME/x

Le compte doit valoir **1**, et `ls` doit dire « No such file ». Les deux
comptent : mesuré, hook retiré du `crushrc`, le compte tombe à 0 **et le
fichier est créé**. `--debug` n'est pas nécessaire — la ligne est de niveau
INFO.

La même vérification vaut pour l'image montée, avec les deux moitiés de la
règle — ce qui doit passer, et ce qui ne doit pas :

    crush run "lis mnt/etc/os-release, puis copie /etc/hosts dans mnt/etc/" >/dev/null 2>&1
    ls ~/analyse/mnt/etc/hosts          # doit dire « No such file »

Le montage en lecture seule, lui, tient dans tous les cas — c'est la seule
garantie réelle ; le reste est une ceinture.

Un dossier qui n'est PAS une collecte et qu'on veut protéger quand même se
liste un par ligne dans `~/.config/crush/scelles.txt` — en plus de la
reconnaissance par structure, jamais à sa place.

### L'image montée : à lire, jamais à écrire

Une collecte ne porte jamais tout. Quand une pièce manque, le geste le plus
rapide est d'aller la lire sur l'image elle-même — et les deux skills sont
faits pour le faire seuls. Montez-la **en lecture seule**, à côté du dossier
d'analyse :

    sudo losetup -r -f --show -P image.dd          # -r : le périphérique est ro
    sudo mount -o ro,noatime /dev/loop0p2 ~/analyse/mnt

`mnt/` est la convention, pas une adresse : **rien n'est écrit en dur nulle
part**. Indiquez au modèle un autre point de montage et il s'en servira ; la
garde le reconnaîtra de la même façon, à sa STRUCTURE — une racine Linux porte
`etc/` et `usr/`.

Ce que la garde laisse faire, et ce qu'elle refuse :

| | |
|---|---|
| `cat mnt/etc/os-release`, `stat`, `find`, `grep -r`, `strings`, `sqlite3`, `tar -t` | **permis** — c'est l'intérêt |
| `strings mnt/var/log/wtmp > ~/analyse/w.txt` | **permis** — la sortie va hors de l'image |
| `strings mnt/… > mnt/tmp/w.txt`, `cp x mnt/etc/`, `rm mnt/…`, `sed -i`, l'outil `write` | **refusés** |

Le montage `ro` suffirait ; la garde est là pour **l'expliquer** au modèle plutôt
que de le laisser buter sur un « read-only file system » qu'il prendrait pour
une panne.

Une pièce lue sur l'image **n'a pas d'empreinte au manifeste** : les deux
`SKILL.md` demandent de la citer comme venant de l'image, et — quand elle fonde
une conclusion — de la recopier dans la collecte avant de relancer
l'extraction, pour qu'elle y entre avec son empreinte. Le tableau
`## Où poser une pièce reprise à la main`, dans
`forensic-linux/references/ou-chercher.md`, donne le nom attendu de chacune.

## 4 · S'en servir

### La méthode sûre, en deux temps

Lancez l'extraction **vous-même**, hors de l'agent :

    C=/mnt/scelles/LINUX/PRJ/PC01_B13_SYCOBS_LINUX
    K="${CRUSH_SKILLS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/crush/skills}"
    python3 $K/forensic-linux/scripts/extraire.py   "$C" -o ~/analyse/faits.jsonl
    python3 $K/conformite-linux/scripts/controles.py "$C" -o ~/analyse/constats.jsonl

Les options de `extraire.py`, toutes facultatives :

| option | à quoi ça sert |
|---|---|
| `--textes fichier` | des chaînes à chercher, **une par ligne, sans syntaxe** — noms, références, mots-clés. Répétable |
| `--indicateurs fichier` | le format riche : `sha256:`, `ip:`, `domaine:`, `regex:`, `fichier:`… (`references/indicateurs.md`) |
| `--sans-reprise` | ignorer le journal de progression et tout reparcourir |

Une extraction qui plante se relance **avec la même commande** : elle reprend
là où elle s'était arrêtée, et rend le même fichier de faits, identifiants
compris.

Si vos règles sont déjà écrites dans un fichier `.regles`, donnez-le, avec les
faits — ce sont eux qui portent les dates et le fuseau du poste :

    python3 $K/conformite-linux/scripts/controles.py "$C" \
            --regles $K/conformite-linux/references/regles/usage-non-professionnel.regles \
            --faits ~/analyse/faits.jsonl -o ~/analyse/constats.jsonl

Ce fichier s'écrit à la main : une règle par bloc, la phrase de la charte
recopiée, puis les indices à chercher. **Relisez-le contre la charte de
l'entreprise avant de vous en servir** : il n'en est pas la copie.

Puis faites produire les **brouillons** — les tableaux du rapport, remplis
depuis les faits, avec des passages « À rédiger » :

    python3 $K/forensic-linux/scripts/brouillon.py    ~/analyse/faits.jsonl    -o ~/analyse/rapport-forensic.md
    python3 $K/conformite-linux/scripts/brouillon.py  ~/analyse/constats.jsonl -o ~/analyse/rapport-conformite.md

Puis ouvrez l'agent dans `~/analyse` et demandez-lui de rédiger. Il n'a alors
besoin que de **lire** les faits et d'**éditer** le brouillon — pas d'exécuter
quoi que ce soit. C'est ce qui rend un modèle de taille moyenne fiable ici :
il ne retape aucune date, aucun identifiant ; il écrit entre des tableaux
qu'un script a remplis.

C'est la méthode à préférer avec une configuration Crush restreinte, du genre :

```json
"permissions": { "allowed_tools": ["view", "ls", "grep", "glob"] }
```

Ces outils sont en lecture seule, et suffisent pour lire les faits. Pour
remplir le brouillon, l'agent a besoin d'`edit` — **ne le pré-autorisez pas** :
absent de `allowed_tools`, chaque édition passe par une demande de permission
qui affiche le chemin touché, et vous n'acceptez que celles qui visent le
dossier d'analyse. C'est un clic par passage rédigé ; c'est le prix d'un
scellé intact. **N'ajoutez pas `bash`** : ce serait accorder le droit d'écrire
partout, y compris dans les scellés, pour une commande que vous pouvez lancer à
la main.

Si vous savez ce que vous cherchez — une empreinte, une adresse, un mot —,
donnez-le à l'extraction :

    python3 $K/forensic-linux/scripts/extraire.py "$C" -o ~/analyse/faits.jsonl \
            --indicateurs ~/analyse/ce-que-je-cherche.txt

Le format tient en une ligne par indicateur (`sha256: …`, `texte: …`,
`ip: …`, `fichier: *.torrent`) : `forensic-linux/references/indicateurs.md`.

### Ou d'un seul geste

Si l'agent a le droit d'exécuter des commandes et que les scellés sont montés
en lecture seule :

    /forensic-linux

puis donnez-lui le dossier de collecte — celui qui porte le PREFIX et contient
`SYSTEME/`, `COMPTES/`, `TIMELINE/`…

> **En `crush run`, rien ne demande.** La session non interactive auto-approuve
> toutes les permissions (`internal/app/app.go:352`, « *Automatically approve
> all permission requests for this non-interactive session* »). Les demandes
> de confirmation décrites plus haut n'existent que dans l'interface
> interactive. En `crush run`, il ne reste que **le montage en lecture seule et
> la garde des scellés** — d'où l'importance de vérifier que la garde est
> réellement armée, et pas seulement qu'elle rend 2 toute seule.

## 5 · Ce que l'extraction produit

    faits.jsonl              un fait par ligne — pour un SIEM, pour grep
    faits.csv                les mêmes faits, pour un tableur, donc pour un humain
    faits-manifeste.json     les empreintes de ce qui a été lu
    faits-reprise.jsonl      le journal de progression : relancez la même
                             commande après un plantage, elle reprend là
    rapport-forensic-….md    le brouillon : tableaux remplis, prose à écrire

Le CSV est écrit avec `;` et un BOM — Excel et LibreOffice l'ouvrent sans
dialogue en français — et **toute cellule qui commence par `=`, `+`, `-`, `@`
ou `|` est précédée d'une apostrophe** : un nom de fichier `=HYPERLINK(...)`
tiré d'une collecte hostile ne deviendra pas une formule dans le tableur de
qui lira le rapport. Le `.jsonl` reste la référence ; le `.csv` en est la vue.

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

## 7 · Si la collecte est grosse — le contexte du modèle est petit

Un `faits.jsonl` de plusieurs dizaines de milliers de lignes ne tient pas dans
une fenêtre de contexte, et un modèle qui lit trop oublie ce qu'il a lu. Trois
règles :

- **le brouillon d'abord** : ses tableaux sont bornés (`--lignes`, 300 par
  défaut) et il dit lui-même ce qu'il a laissé dehors et comment le lire ;
- **une section à la fois** : le modèle lit une section du brouillon, la
  rédige, passe à la suivante — jamais le fichier entier ;
- **`grep` plutôt que `view`** sur `faits.jsonl` : par catégorie, par compte,
  par identifiant.

Découpez par catégorie plutôt que tout charger :

    grep '"categorie":"evenement"'      faits.jsonl > evenements.jsonl
    grep '"categorie":"suspect"'        faits.jsonl > suspects.jsonl
    grep '"categorie":"telechargement"' faits.jsonl > telechargements.jsonl

Les catégories : `machine`, `compte`, `domaine`, `evenement`, `periode`,
`support`, `appareil`, `reseau`, `navigation`, `telechargement`, `usage`,
`persistance`, `suspect`, `paquet`, `timeline`, `chaines`, `document`,
`recuperation`, `indicateur`, `interet`, `limite`. **L'extraction les récapitule
en fin de course** — c'est cette ligne qui fait foi, pas celle-ci.

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

Le sous-agent emploie le modèle **large**, et **rien ne permet de le changer** :
`Config.Agents` porte `json:"-"` (`internal/config/config.go:762`), le schéma
est en `additionalProperties: false` sans clé `agents`, et le modèle du
sous-agent est écrit en dur (`config.go:959`). Un bloc `"agents": {…}` dans un
`crush.json` est ignoré en silence.

Le skill dit quoi leur demander, et surtout ce qu'ils ne doivent pas faire :
lire et résumer, jamais conclure ni qualifier.

### Suivre une analyse longue

Crush expose aussi **`todos`**. Le skill s'en sert pour poser les dix sections
du rapport avant de commencer : une analyse s'interrompt, la liste dit où on en
était. Inutile de l'ajouter aux permissions : `todos` n'en demande aucune —
il ne reçoit même pas le service de permissions (`coordinator.go:789`). Même
chose pour `grep`, `glob` et `crush_info` ; parmi les outils de lecture, seuls
`view` et `ls` demandent.

## 8 · Vérifier l'extracteur

Sur un poste neuf, avant de s'en servir sur une vraie affaire :

    python3 -m py_compile forensic-linux/scripts/*.py conformite-linux/scripts/*.py
    python3 forensic-linux/scripts/extraire.py --help

Puis sur une collecte connue, deux fois de suite :

    python3 … -o /tmp/a.jsonl && python3 … -o /tmp/b.jsonl && cmp /tmp/a.jsonl /tmp/b.jsonl

Les deux doivent être identiques. S'ils diffèrent, quelque chose a bougé dans
la collecte entre les deux lectures — c'est un fait en soi, et grave. Le même
test vaut pour `controles.py` et pour les deux `brouillon.py` : à faits
identiques, brouillons identiques.

### Les distributions

La collecte et les deux skills sont vérifiés sur une **matrice de cinq
familles**, chacune avec les pièces qui lui sont propres et sans celles qui
n'existent pas chez elle :

| famille | ce qui la distingue, et qui est testé |
|---|---|
| Fedora 40+ / RHEL récent | `rpm -qa --last` (en français), historique dnf5 en sqlite, `wtmp.db` et `lastlog2.db` (dates en microsecondes), journal systemd seul |
| Debian 13+ / Ubuntu | `dpkg-query`, `dpkg.log` et `apt/history.log` (dont les tournés `.gz`), `wtmp.db`, `auth.log` sans année, `wpa_supplicant`, netplan |
| openSUSE | `zypp/history` (commandes en `#`), base RPM `ndb` que `rpm` ne lit pas — la liste vide devient une limite, pas un « 0 paquet » |
| Arch | `var/lib/pacman/local` (la pose datée par `%INSTALLDATE%`), `pacman.log`, profils `iwd` (SSID en hexadécimal compris) |
| Alpine | `apk` (`lib/apk/db/installed`, `etc/apk/world`), ni `wtmp` ni journal systemd — l'extraction le dit **normal** au lieu de le compter manquant, syslog de busybox |

    tests/plan.sh                                # la conf elle-même : son plan sur un faux montage par famille
    python3 tests/matrice.py /tmp/matrice        # cinq collectes synthétiques
    for c in /tmp/matrice/*/ ; do python3 forensic-linux/scripts/extraire.py "$c" -o "$c.jsonl" ; done
    python3 tests/artefacts.py /tmp/artefacts    # chaque pièce sert-elle à quelque chose ?

Chaque bloc du générateur dit ce que la famille doit donner. **Une pièce
ajoutée à `collecte-linux.conf` se reflète dans `tests/matrice.py`, ou elle
n'est pas testée** — c'est cette matrice qui a révélé que `wtmp.db` compte en
microsecondes et que `zypp` note ses commandes en commentaire.

### Chaque pièce sert-elle à quelque chose ?

`tests/artefacts.py` répond à l'autre moitié de la question. Il fabrique **une**
collecte qui porte toutes les pièces — et qui est piégée : un film copié sur une
clé USB, un marque-page vers un site de torrent, une recherche tapée dans la
barre d'adresse, un mineur en autostart, une unité systemd qui lance depuis
`/tmp`, une clé SSH commune à deux comptes, un `su` vers le compte d'un
collègue. Puis il lance les deux extracteurs et **vérifie que chaque artefact a
produit le fait ou le constat qu'on en attend** — 65 aujourd'hui — et sort en
erreur en nommant ceux qui n'ont rien donné.

C'est ce qui interdit de collecter une pièce pour rien : elle apparaît dans la
liste avec la mention `MANQUE` tant que personne ne la lit. C'est ainsi que la
timeline, les marque-pages, les saisies de formulaire, les applications snap et
flatpak, les unités systemd, `fstab` et la sortie de photorec sont entrés dans
les faits.

Une seule collecte réelle a servi en plus : un CentOS 7. Les autres familles
sont synthétiques — fidèles aux formats, pas à la vie d'un poste. La première
collecte réelle de chaque famille mérite une relecture attentive des limites.

Deux blocs sont recopiés d'un skill à l'autre, délimités par `# ── commun ──`
et `# ── fin commun ──` — lecture du JSONL, tableau Markdown et horloge dans
les deux `brouillon.py` ; lecture des réseaux sans fil dans `extraire.py` et
`controles.py`. Chaque skill doit rester installable seul, et chaque bloc doit
rester identique. Pour vérifier qu'ils n'ont pas dérivé :

    diff <(sed -n '/^# ── commun ──/,/^# ── fin commun ──/p' forensic-linux/scripts/brouillon.py) \
         <(sed -n '/^# ── commun ──/,/^# ── fin commun ──/p' conformite-linux/scripts/brouillon.py)
    diff <(sed -n '/^# ── commun ──/,/^# ── fin commun ──/p' forensic-linux/scripts/extraire.py) \
         <(sed -n '/^# ── commun ──/,/^# ── fin commun ──/p' conformite-linux/scripts/controles.py)

---

## 9 · Crush et Nemotron 3 Super : la configuration, et pourquoi

`crushrc` (ou `crush.json`, déprécié — voir §2) posé à côté est prêt à
l'emploi, **sauf trois valeurs qui dépendent de votre poste** : `base_url`, le
dossier personnel dans les chemins du `crush.json`, et `context_window`. Le
reste, et d'où ça vient :

| réglage | valeur | pourquoi |
|---|---|---|
| `providers.dgx.type` | `openai-compat` | vLLM, NIM et TRT-LLM exposent tous l'API OpenAI |
| `temperature`, `top_p` | `1.0`, `0.95` | la carte du modèle : « Use `temperature=1.0` and `top_p=0.95` across **all tasks and serving backends** — reasoning, tool calling, and general chat alike » |
| `extra_body.chat_template_kwargs.enable_thinking` | `true` | le raisonnement du modèle s'active par ce drapeau du gabarit de conversation ; `extra_body` n'existe que pour les fournisseurs compatibles OpenAI, et c'est le bon canal. `low_effort: true` allège le raisonnement, `reasoning_budget` le plafonne |
| `context_window` | `240000` (livré) | ce que **déclare le checkpoint** est 262144 : `max_position_embeddings` vaut 262144 dans `config.json`, en BF16 comme en FP8, avec `rope_scaling` à `null`. Le million de jetons se demande explicitement — voir ci-dessous |
| `default_max_tokens` | `16000` (livré) | un brouillon se rédige passage par passage ; 16 k tiennent les deux bouts — voir le calcul plus bas. Ce n'est qu'un repli : `models.large.max_tokens` prime (`coordinator.go:282`) |
| `permissions.allowed_tools` | `view ls grep glob agent` | c'est une liste de **pré-approbation**, pas une liste blanche (`config.go:333`) : `edit` et `bash` ne sont pas interdits, ils **demandent**. Un « autoriser pour cette session » accorde ensuite `bash` sans limite. Pour l'interdire vraiment : `permissions deny bash` |
| `options.disabled_tools` | `fetch agentic_fetch sourcegraph download` | le poste est hors ligne : autant que le modèle ne voie pas ces outils, plutôt qu'il les essaie. `download` s'y ajoute parce qu'il écrit en plus sur le disque |
| `options.data_directory` | dossier d'analyse | la base de Crush (sessions, journaux) vit dans le dossier d'analyse, jamais dans les scellés. En `crush.json`, ce chemin doit être **absolu** : un `~` n'y est pas développé |
| `hooks.PreToolUse` | `garde-scelles.sh` | avant chaque `edit`, `write`, `multiedit`, `bash` ou `download`, le script reçoit l'appel en JSON sur son entrée standard et **le bloque (code 2)** s'il nomme un chemin sous les scellés ; son message d'erreur devient le motif du refus rendu au modèle. `PreToolUse` est aujourd'hui le **seul** événement que Crush déclenche |

Le modèle : 120 milliards de paramètres dont 12 actifs par jeton, hybride
Mamba-2 / attention / experts. Ce qui compte pour ces skills : il est entraîné
aux appels d'outils multi-étapes, et ses deux faiblesses documentées en usage
agentique sont **la dérive de l'objectif** quand le contexte s'allonge et **les
appels d'outils malformés**. Le brouillon répond à la première (le plan est sur
disque, le modèle remplit un passage à la fois) ; la lecture seule répond à la
seconde (un appel malformé ne peut rien casser).

### Servir le modèle : trois options sans lesquelles les skills ne marchent pas

Les deux skills fonctionnent **entièrement par appels d'outils**. Trois options
de la carte du modèle sont donc indispensables, et deux d'entre elles ne
s'inventent pas :

| option vLLM | pourquoi |
|---|---|
| `--enable-auto-tool-choice` | sans elle, le modèle n'appelle aucun outil : Crush n'ouvre pas un fichier |
| `--tool-call-parser qwen3_coder` | le format d'appel d'outils de ce modèle ; un autre parseur laisse `tool_calls` à `null` malgré une invite correcte |
| `--reasoning-parser nemotron_v3` | sépare la trace de raisonnement de la réponse. Mal réglé, le raisonnement **déborde dans les arguments des outils** — et dans le rapport |
| `--kv-cache-dtype fp8` | recommandé par NVIDIA **et** par le billet vLLM ; c'est ce qui rend le contexte long tenable en mémoire |
| `--gpu-memory-utilization 0.85` à `0.9` | 0.9 dans la carte du modèle, 0.85 dans le billet vLLM ; commencez à 0.85 |

Les quatre modes de panne connus de ce montage, pour les reconnaître :
`tool_calls` à `null` (mauvais parseur d'outils) · du texte de raisonnement dans
les arguments (parseur de raisonnement mal réglé) · `finish_reason: "length"`
avant même que l'appel d'outil sorte (`max_tokens` trop petit — le raisonnement
est émis **avant** l'appel et se compte dessus) · l'agent qui refait deux fois
la même action (les résultats d'outil ne lui reviennent pas).

Et un détail qui compte quand la machine est coupée d'Internet : ces backends
réclament un parseur de raisonnement **à télécharger séparément**. Prenez-le
**avant** de débrancher le réseau :

    curl -O https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16/raw/main/super_v3_reasoning_parser.py

Pour mémoire : 8× H100-80GB au minimum, et 2 GPU suffisent en BF16 sur B200 ou
B300 (`--tensor-parallel-size 2`, sans `--enable-expert-parallel`).

### Régler les tailles : une contrainte, pas trois nombres

Trois valeurs se tiennent, et les régler séparément fait échouer la session en
plein rapport. Avec **S** = ce que sert `--max-model-len` et **M** = la marge de
résumé de Crush (20 000 si `context_window` dépasse 200 000, sinon 20 % de
`context_window`) :

    (context_window − M) + plus gros résultat d'outil + max_tokens  ≤  S

**`context_window` reste sous S, jamais égal** — c'est la leçon de ceux qui ont
branché un agent sur vLLM avant nous : annoncer le maximum théorique fait
empaqueter des invites que le serveur refuse ensuite, en pleine session. Égal à
S, ça dépasse même avec un `max_tokens` modeste, parce que le contrôle de Crush
n'a lieu qu'**entre deux étapes**. Le plus gros résultat d'outil, ici, c'est
relire le rapport en cours : 20 à 30 k jetons pour 1 500 lignes.

**`max_tokens` a un plancher autant qu'un plafond** : le raisonnement est émis
*avant* l'appel d'outil et se compte dessus, donc trop petit, la réponse est
tronquée (`finish_reason: "length"`) avant même que l'outil parte. 16 000 tient
les deux bouts.

Pour `max_tokens` 16 000 et un pic d'outil de 25 000 :

| servi (`--max-model-len`) | `context_window` | pire cas | verdict |
|---|---|---|---|
| 131 072 | 131 072 | 145 858 | dépasse de 14 786 |
| 131 072 | 110 000 | 129 000 | tient |
| 262 144 | 262 144 | 283 144 | dépasse de 21 000 |
| 262 144 | **240 000** | 261 000 | tient — c'est le réglage livré |

**Servir plus large vaut mieux que de bien régler.** À 131 072, Crush résume dès
105 000 jetons, et chaque résumé perd du détail — ce qu'on ne veut pas dans un
rapport où chaque fait cite sa source ; à 240 000, le premier résumé n'arrive
qu'à 220 000. Le checkpoint déclare 262144, et le million annoncé par NVIDIA est
réel (RULER @ 1M : 91,75) mais se demande :

    VLLM_ALLOW_LONG_MAX_MODEL_LEN=1 vllm serve … --max-model-len 1048576
    # SGLang : SGLANG_ALLOW_OVERWRITE_LONGER_CONTEXT_LEN=1 --context-length 1048576

Dans le doute, la valeur servie fait foi et se lit sur le serveur :

    curl -s http://dgx.local:8000/v1/models | python3 -m json.tool

### Ce qui reste à confirmer sur votre poste

Deux points n'ont pas pu être tranchés sans lancer Crush contre votre serveur,
et il vaut mieux le dire que le laisser croire :

  - **le nom du modèle dans `crushrc`.** Les builtins prennent la forme
    `<provider>/<id>`, or l'identifiant Nemotron contient déjà une barre
    oblique : `dgx/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B`. La découpe se
    fait selon toute vraisemblance sur la **première** barre. Pour le vérifier,
    `model large` sans argument, dans un `crushrc`, imprime la sélection
    courante sous la forme attendue ; et l'identifiant réellement servi se lit
    par `curl -s http://dgx.local:8000/v1/models`. (Plus simple : **`crush models`** le
    dit — la sous-commande existe, elle est enregistrée dans un `init()`
    (`internal/cmd/models.go:16,154`), ce qui explique qu'elle manque au bloc
    `AddCommand` de `root.go`. `crush server` de même.) ;
  - **la tolérance de `_commentaire`** dans `crush.json`. Le schéma est en
    `additionalProperties: false` ; Go ignore les clés inconnues, mais si votre
    éditeur la souligne ou si Crush la refuse, supprimez le bloc : c'est de la
    documentation, rien n'en dépend. N'y mettez **pas** de commentaires `//` :
    Crush n'embarque pas de parseur JSONC, et la configuration entière serait
    perdue.

Sources, à relire si une version change : la carte du modèle et le `config.json`
sur Hugging Face — `nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16`
(échantillonnage, `chat_template_kwargs`, `max_position_embeddings`, options de
service, RULER @ 1M) ; le schéma
`https://charm.land/crush.json` (`extra_body`, `hooks`, `disabled_tools`,
`data_directory`, bornes de `temperature`, `top_p` et `max_tokens`) ; le README
de Crush (formats de configuration, dossiers, dépréciation du JSON) ; et
`docs/hooks/` du dépôt Crush (charge utile sur stdin, codes de sortie).

## Le skill de conformité, en deux mots

Il ne juge rien sans règle écrite. Le script relève des **constats** — « clé
privée SSH sans phrase de passe », « `PermitRootLogin yes` », « fichiers d'un
autre compte dans ce dossier personnel » — chacun accompagné de la **question**
à laquelle une règle devra répondre pour en faire un manquement. Le
rapprochement est le travail du rapport, et le skill impose de le **montrer** :
un tableau « règle → contrôle retenu » avant tout résultat, pour qu'un lecteur
puisse contester la méthode avant les conclusions.

Les règles s'écrivent dans un fichier `.regles`, à la main : une règle par
bloc, sa phrase recopiée de la charte, puis les indices — un domaine, un
programme, un fichier, une commande, un réseau sans fil, un horaire, une
chaîne, ou un contrôle fixe du script (`controle: partage`). Ajouter une règle,
c'est ajouter un bloc.

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
