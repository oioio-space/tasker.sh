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

### Où Crush cherche vraiment

Crush distingue deux dossiers, et ils ne portent pas le même nom. **Le second
n'est pas un endroit où poser quoi que ce soit :**

| dossier | ce que c'est | ce qu'on y met |
|---|---|---|
| `~/.config/crush/` | la **configuration** — `crushrc`, `skills/` | vos fichiers |
| `~/.local/share/crush/` | l'**état** de Crush : sessions, cache | rien, jamais |

Le piège est que Crush écrit dans le second un fichier qui s'appelle aussi
`crush.json`. **Ce n'est pas votre configuration** : c'est son état interne, il
le réécrit quand il veut. Une configuration posée là est ignorée, et un skill
posé là n'est jamais trouvé — le dossier d'état ne figure dans aucune des
listes ci-dessous.

Si votre installation est sous `~/.local/`, c'est presque sûrement l'une de ces
deux choses, et **aucune ne change quoi que ce soit à ce qui suit** :

  - `~/.local/bin/crush` : le **binaire**, posé là par le script d'installation
    quand il tourne sans les droits root. Où vit le programme n'a rien à voir
    avec où il lit sa configuration ;
  - `~/.local/share/crush/` : le dossier d'état ci-dessus.

Pour les skills, Crush regarde d'office ces quatre dossiers — le premier venu
suffit, il n'y a **rien à déclarer** dans `crush.json` :

    ~/.config/crush/skills/     ~/.agents/skills/
    ~/.config/agents/skills/    ~/.claude/skills/

et, dans le dossier de travail courant, `.crush/skills/`, `.agents/skills/`,
`.claude/skills/` et `.cursor/skills/`.

Deux réglages déplacent tout ça, et c'est la seule raison pour laquelle votre
machine pourrait différer : `XDG_CONFIG_HOME`, qui remplace `~/.config`, et
`CRUSH_SKILLS_DIR`, qui **remplace les quatre dossiers d'un coup** par celui
qu'il nomme. Vérifiez sur votre poste avant de copier quoi que ce soit :

    echo "config : ${XDG_CONFIG_HOME:-$HOME/.config}/crush"
    echo "skills  : ${CRUSH_SKILLS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/crush/skills}"
    ls -d ~/.config/crush ~/.local/share/crush ~/.claude/skills 2>/dev/null

### Poser les skills

Pour Crush, une fois pour toutes :

    K="${CRUSH_SKILLS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/crush/skills}"
    C="${XDG_CONFIG_HOME:-$HOME/.config}/crush"
    mkdir -p "$K" "$C"
    cp -r exemples/skills/forensic-linux exemples/skills/conformite-linux "$K/"
    cp exemples/skills/garde-scelles.sh "$C/" && chmod +x "$C/garde-scelles.sh"
    cp exemples/skills/crushrc    "$C/crushrc"             # puis adaptez base_url

Ou seulement pour un dossier de travail — c'est le plus simple si vous voulez
un jeu de skills par affaire :

    mkdir -p ~/analyse/.crush/skills
    cp -r exemples/skills/forensic-linux ~/analyse/.crush/skills/

Dans les deux cas, Crush doit lister les deux skills au démarrage. S'il ne les
voit pas, c'est le chemin, pas le skill : relancez les trois commandes de
vérification ci-dessus.

### Deux formats, un seul à préférer

Crush a changé de format de configuration. Le README de Crush est net :

> What about the old JSON format? It's still supported, but it should be
> considered deprecated.

Le format courant est le **`crushrc`** — du Bash avec quelques builtins
(`provider add`, `model large`, `permissions allow`, `hook add`, `option`),
cherché dans `./.crushrc`, `./crushrc`, puis `~/.config/crush/crushrc`. Les
deux fichiers sont fournis et font la même chose :

| fichier | format | à préférer |
|---|---|---|
| `crushrc` | Bash, format courant | **oui** |
| `crush.json` | JSON, déprécié mais toujours accepté | seulement si votre version de Crush est ancienne |

Ce n'est pas qu'une question de mode : un `crushrc` est un shell, donc `$HOME`
et `XDG_CONFIG_HOME` y sont **réellement développés, partout**. En `crush.json`,
le `~` n'est développé que dans certains champs — et il fallait lire le code de
Crush pour savoir lesquels :

| champ de `crush.json` | le `~` marche ? | pourquoi |
|---|---|---|
| `hooks[].command` | **oui** | la commande passe par le shell POSIX embarqué (`shell.Run`), qui développe le `~` comme n'importe quel shell |
| `options.data_directory` | **non** | `SmartJoin` ne teste que `filepath.IsAbs` : Crush crée un dossier nommé `~` dans le dossier courant |
| `options.skills_paths` | **non** | le chemin part tel quel dans `fastwalk.Walk`, sans expansion — même si le schéma en donne un en exemple |
| `api_key`, `base_url`, `env` | non, mais… | `$VAR`, `${VAR:-defaut}` et `$(cmd)` y sont développés |

C'est pour ça que le `crush.json` fourni écrit `/home/analyste/…` pour
`data_directory` et `skills_paths` — **remplacez-le par votre vrai dossier
personnel** — et garde le `~` pour le hook, où il fonctionne.

La consigne « chemin absolu » de `docs/hooks/` ne parle pas du `~` : elle vise
les chemins **relatifs** (`./mon-hook.sh`), résolus depuis le dossier de
travail et non depuis la configuration.

En revanche, `crushrc` est **du code exécuté au lancement**, dans un shell
complet — et `crush.json` n'est pas inerte non plus : tout `$(...)` qui s'y
trouve est exécuté au chargement. Ne lancez pas Crush dans un dossier dont vous
n'avez pas lu la configuration.

`garde-scelles.sh` est la ceinture décrite au §3 ; le §9 explique les réglages
du modèle.

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
buter sur un « permission denied ». Mais un hook dont le chemin ne se résout
pas **ne bloque rien, et ne dit rien** — c'est le seul mode de panne dangereux,
parce qu'il est silencieux. Alors on le vérifie, hors de Crush :

    printf '{"tool_name":"write","tool_input":{"file_path":"/mnt/scelles/x"},"cwd":"/tmp"}' \
        | ~/.config/crush/garde-scelles.sh ; echo "code $?"

Le script doit écrire son refus et rendre **2**. Un code 0, ou « command not
found », veut dire que la ceinture est absente : le fichier n'est pas là où le
hook le nomme, ou il n'est pas exécutable. Le montage en lecture seule, lui,
tient toujours.

Les dossiers protégés se listent un par ligne dans
`~/.config/crush/scelles.txt` ; sans ce fichier, c'est `/mnt/scelles`.

## 4 · S'en servir

### La méthode sûre, en deux temps

Lancez l'extraction **vous-même**, hors de l'agent :

    C=/mnt/scelles/LINUX/PRJ/PC01_B13_SYCOBS_LINUX
    K="${CRUSH_SKILLS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/crush/skills}"
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

## 5 · Ce que l'extraction produit

    faits.jsonl              un fait par ligne — pour un SIEM, pour grep
    faits.csv                les mêmes faits, pour un tableur, donc pour un humain
    faits-manifeste.json     les empreintes de ce qui a été lu
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
| `context_window` | `262144` | ce que **déclare le checkpoint** : `max_position_embeddings` vaut 262144 dans `config.json`, en BF16 comme en FP8, avec `rope_scaling` à `null`. Le million de jetons se demande explicitement — voir ci-dessous |
| `default_max_tokens` | `32000` | un brouillon se rédige passage par passage ; 32 k suffisent et bornent une réponse qui s'emballerait |
| `permissions.allowed_tools` | `view ls grep glob agent` | lecture seule + sous-agents ; `edit` demande à chaque fois, `bash` n'est jamais accordé |
| `options.disabled_tools` | `fetch web_search sourcegraph download` | le poste est hors ligne : autant que le modèle ne voie pas ces outils, plutôt qu'il les essaie. `download` s'y ajoute parce qu'il écrit en plus sur le disque |
| `options.data_directory` | dossier d'analyse | la base de Crush (sessions, journaux) vit dans le dossier d'analyse, jamais dans les scellés. En `crush.json`, ce chemin doit être **absolu** : un `~` n'y est pas développé |
| `hooks.PreToolUse` | `garde-scelles.sh` | avant chaque `edit`, `write`, `multiedit`, `bash` ou `download`, le script reçoit l'appel en JSON sur son entrée standard et **le bloque (code 2)** s'il nomme un chemin sous les scellés ; son message d'erreur devient le motif du refus rendu au modèle. `PreToolUse` est aujourd'hui le **seul** événement que Crush déclenche |

Le modèle : 120 milliards de paramètres dont 12 actifs par jeton, hybride
Mamba-2 / attention / experts. Ce qui compte pour ces skills : il est entraîné
aux appels d'outils multi-étapes, et ses deux faiblesses documentées en usage
agentique sont **la dérive de l'objectif** quand le contexte s'allonge et **les
appels d'outils malformés**. Le brouillon répond à la première (le plan est sur
disque, le modèle remplit un passage à la fois) ; la lecture seule répond à la
seconde (un appel malformé ne peut rien casser).

### Le contexte : 256 k par défaut, 1 M sur demande

Le million de jetons annoncé par NVIDIA n'est pas une figure de style — RULER
@ 1M donne **91,75**, ce qui est très bon — mais il **ne s'obtient pas tout
seul**. La carte du modèle est explicite :

> Please note that the model supports up to a 1M context size, although the
> default context size in the Hugging Face configuration is 256k due to higher
> VRAM requirements.

Autrement dit, ce n'est pas vLLM qui rogne un modèle à 1 M : c'est le
checkpoint lui-même qui déclare 262144. Pour aller au-delà :

    VLLM_ALLOW_LONG_MAX_MODEL_LEN=1 vllm serve … --max-model-len 1048576
    # SGLang : SGLANG_ALLOW_OVERWRITE_LONGER_CONTEXT_LEN=1 --context-length 1048576

Si vous le faites, **portez la même valeur dans `context_window`**, sinon Crush
se croira borné à 256 k. Pour ces skills, ça change quelque chose : une
timeline mactime et un `faits.jsonl` de gros dossier tiennent plus large. Dans
le doute, la valeur servie fait foi et se lit sur le serveur :

    curl -s http://dgx.local:8000/v1/models | python3 -m json.tool

### Servir le modèle : trois options sans lesquelles les skills ne marchent pas

Les deux skills fonctionnent **entièrement par appels d'outils**. Trois options
de la carte du modèle sont donc indispensables, et deux d'entre elles ne
s'inventent pas :

| option vLLM | pourquoi |
|---|---|
| `--enable-auto-tool-choice` | sans elle, le modèle n'appelle aucun outil : Crush n'ouvre pas un fichier |
| `--tool-call-parser qwen3_coder` | le format d'appel d'outils de ce modèle ; un autre parseur rend des appels malformés |
| `--reasoning-parser nemotron_v3` | sépare la trace de raisonnement de la réponse ; sans elle, le raisonnement se retrouve dans le rapport |

Et un détail qui compte quand la machine est coupée d'Internet : ces backends
réclament un parseur de raisonnement **à télécharger séparément**. Prenez-le
**avant** de débrancher le réseau :

    curl -O https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16/raw/main/super_v3_reasoning_parser.py

Pour mémoire : 8× H100-80GB au minimum, et 2 GPU suffisent en BF16 sur B200 ou
B300 (`--tensor-parallel-size 2`, sans `--enable-expert-parallel`).

### Ce qui reste à confirmer sur votre poste

Deux points n'ont pas pu être tranchés sans lancer Crush contre votre serveur,
et il vaut mieux le dire que le laisser croire :

  - **le nom du modèle dans `crushrc`.** Les builtins prennent la forme
    `<provider>/<id>`, or l'identifiant Nemotron contient déjà une barre
    oblique : `dgx/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B`. La découpe se
    fait selon toute vraisemblance sur la **première** barre, mais vérifiez-le
    d'un `crush models`, qui imprime la forme attendue ;
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
