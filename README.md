# tasker.sh

Enchaîne des commandes, **validées une à une**. Un tableau de lignes, un
journal, et de quoi répéter une étape sur une liste de valeurs.

```bash
./tasker.sh -h          # l'aide
./tasker.sh -h tout     # le manuel complet, dans le script
./tasker.sh -l          # voir le plan sans rien lancer
./tasker.sh             # lancer
```

Le script se suffit à lui-même : copié seul sur une machine, `-h` explique
tout — la ligne d'étape, les valeurs, les listes fournies, le fichier `-c`,
et un cas complet à copier (`-h etapes`, `-h valeurs`, `-h outils`,
`-h config`, `-h exemple`). Ce README est le même contenu, en plus confortable.

Prérequis : bash 4.3 (sur macOS : `brew install bash`, puis `/opt/homebrew/bin/bash tasker.sh`).
Pour comprendre en profondeur : **[TUTORIEL.md](TUTORIEL.md)**.

**Un nom qui commence par `TK_` est lu par le script** : remplissez-le, ne le
supprimez pas, ne le renommez pas. Tous les autres noms sont à vous.

Le script est rangé de ce qu'on retouche le plus vers ce qu'on ne touche
jamais :

| | section | ce qu'on y met |
|---|---|---|
| 1 | variables | ce qui change d'un usage à l'autre |
| 2 | réglages | posés une fois : `TK_REQUIS`, `TK_OPERATEUR`, `TK_TOUT_VALIDER`, `TK_MAX_ITERATIONS` |
| 3 | commandes | les étapes |
| 4 | listes | les valeurs sur lesquelles une étape se répète |
| 5 | fonctions | ce que 3 et 4 appellent |
| 6 | chemins et contrôles | `calculer_variables`, `verifier` |
| 7 | mécanique | à ne pas toucher |

---

## Une étape

```bash
"Titre|validation|commande"
```

```bash
"Espace disque|true|df -h /"
"Sauvegarde|false|tar czf /tmp/etc.tgz /etc"
"Journalisée|true,log|dmesg | tail -n 50"
"Optionnelle|true,continu|systemctl status nginx"
"Critique|true,stop|mount /dev/sdb1 /mnt"
```

| validation | effet |
|---|---|
| `true` | demande avant de lancer |
| `false` | lance directement |
| `,log` | la sortie va aussi dans le journal |
| `,continu` | un échec est ignoré, sans question |
| `,stop` | un échec arrête tout, sans question |

Pas de `|` dans le titre. Ceux de la commande sont libres.

---

## Trois façons d'insérer une valeur

### `$VARIABLE` — connue à l'avance

```bash
DOSSIER="/srv/data"                       # section 1
"Contenu|true|ls -la '$DOSSIER'"          # section 3
```

Une variable qui naît **pendant** la commande s'échappe :

```bash
"Boucle|true|for f in '$DOSSIER'/*; do echo \$f; done"
```

### `[[nom]]` — demandée une fois, réutilisée

```bash
"Fichiers récents|true|find '$DOSSIER' -mtime -[[jours]]"
"Leur taille|true|find '$DOSSIER' -mtime -[[jours]] -ls"
```

```
    ┌─ [[jours]]  — utilisé aux étapes 1, 2
    └─ valeur › 7
```

Fournie d'avance : `./tasker.sh -D jours=7`.

Un `[[nom]]` écrit dans le **titre** s'affiche avec la valeur dès qu'elle est
connue — « Purge de plus de 30 jours » plutôt que « … de plus de [[jours]]
jours » — au plan si `-D` l'a fournie, sinon à partir de la question. Il faut
que la commande de l'étape emploie le même `[[nom]]` : c'est elle qui
déclenche la question.

Entre apostrophes de préférence : `'[[nom]]'`. Une valeur qui en contient une
est protégée à l'entrée dans la commande, quelle que soit son origine — menu,
saisie ou `-D`.

### `{{nom}}` — l'étape est rejouée pour chaque valeur

```bash
"Taille de chaque sous-dossier|true|du -sh '{{sousdossier}}'"
```

```
  ↻  étape répétée — 3 itérations
      1  sousdossier=documents
      2  sousdossier=images
      3  sousdossier=projets
```

Toujours entre apostrophes : `'{{nom}}'`.

---

## Les listes (section 4)

Une liste = un nom, et une commande qui écrit **une valeur par ligne**.

```bash
TK_LISTES=(
"jours|printf '%s\n' 1 7 30"
"sousdossier|lister_dossiers '$DOSSIER'"
)
```

### D'abord : ce que la commande écrit

Une commande de liste est une commande ordinaire. Lancez-la dans votre
terminal : ce que vous voyez est exactement ce que le script recevra.

```bash
$ printf '%s\n' 1 7 30
1
7
30
```

Trois lignes, donc trois valeurs — et rien d'autre. Les lignes vides sont
ignorées ; ce qui part sur la sortie d'erreur n'est pas une valeur, ça va
dans le journal.

Ces trois valeurs deviennent ensuite l'une ou l'autre de deux choses, selon
la façon dont une commande les appelle :

| dans la commande | ce qui se passe |
|---|---|
| `[[jours]]` | **menu** : la question propose les valeurs, on en choisit une |
| `{{jours}}` | **répétition** : l'étape est rejouée pour chaque valeur |

### Faire d'une question un menu

Sans liste, `[[jours]]` est une question libre :

```
    ┌─ [[jours]]  — utilisé à l'étape 1
    └─ valeur › 
```

Ajoutez une liste **du même nom** — `jours`, celle d'au-dessus — et la
question devient un menu, une entrée par ligne écrite :

```
    ┌─ [[jours]]  — utilisé à l'étape 1
    │
    │   1  1
    │   2  7
    │   3  30
    │
    │   a  saisir une autre valeur
    │   p  passer cette étape
    │   q  quitter le script
    └─ votre choix [1] › 
```

| touche | effet |
|---|---|
| `2` | prend la 2ᵉ proposition |
| `Entrée` | prend la 1ʳᵉ |
| `a` | tape une valeur qui n'est pas dans la liste |
| `p` | passe l'étape |
| `q` | quitte |

Après `a`, `p` et `q` redeviennent des valeurs ordinaires : une valeur
qui s'appelle `p` se tape `a` puis `p`.

La valeur choisie est **mémorisée** : toutes les étapes qui contiennent
`[[jours]]` l'utilisent sans redemander. Pour la fournir d'avance :
`./tasker.sh -D jours=7`. Pour tout ressaisir sur une étape : `r`.

### La même liste, en répétition

Les trois mêmes lignes, appelées en `{{jours}}` : plus de menu, une
itération par valeur.

```bash
"Fenêtre|true|journalctl --since '{{jours}} days ago'"
```

```
  ↻  étape répétée — 3 itérations
      1  jours=1
      2  jours=7
      3  jours=30
```

Le compte est annoncé **avant** d'exécuter quoi que ce soit.

### Les libellés : une valeur pour la commande, un texte pour vous

Une ligne de liste peut s'écrire `valeur<TAB>libellé` :

```bash
"jours|printf '%s\t%s\n' 1 'hier' 7 'cette semaine' 30 'ce mois'"
```

Ce que la commande écrit, vérifié avec `cat -A` — `^I` est la tabulation,
`$` la fin de ligne :

```bash
$ printf '%s\t%s\n' 1 'hier' 7 'cette semaine' 30 'ce mois' | cat -A
1^Ihier$
7^Icette semaine$
30^Ice mois$
```

Ce contrôle vaut le coup : à l'œil, une tabulation et trois espaces se
ressemblent, mais des espaces resteraient dans la valeur et il n'y aurait
pas de libellé du tout.

Le menu affiche alors les deux colonnes :

```
    │   1  1              hier
    │   2  7              cette semaine
    │   3  30             ce mois
```

Seule la **valeur** (avant la tabulation) entre dans la commande. Le
**libellé** sert à trois choses :

**1. Lire le menu** — ci-dessus : `7` seul ne dit rien, `cette semaine` si.

**2. Lire les itérations** — l'étiquette d'une étape répétée montre le
libellé :

```bash
"home|lister_homes '$IMAGE'"        # écrit : 51-144-1<TAB>Users/alice
"Inventaire|true|inventorier '{{home}}'"
```

```
  ↻  étape répétée — 2 itérations
      1  home=Users/alice            ← le libellé, pas 51-144-1
      2  home=Users/bruno
```

**3. L'utiliser dans la commande** — `{{nom_libelle}}` donne le libellé
de la valeur en cours. Typique : la valeur est ce que l'outil attend (un
inode, un identifiant, un chemin complet), le libellé ce qu'on veut voir
dans un nom de fichier :

```bash
"Inventaire|true|fls '$IMAGE' '{{home}}' > '$TK_DIR_OUT/{{home_libelle}}.txt'"
#                                  ↑ 51-144-1              ↑ Users/alice
```

```bash
"Contenu de chaque home|true|ls -la '{{home}}' > '$TK_DIR_OUT/ls_{{home_libelle}}.txt'"
#                                      ↑ /home/alice              ↑ alice
```

Sans tabulation, `{{nom_libelle}}` vaut simplement la valeur.

### Une liste qui en utilise une autre

```bash
"profil|lister_dossiers '/home'"
"bashrc|lister_bashrc '{{profil}}'"       # dépend de profil
```

```bash
"Chaque .bashrc|true|cat '{{bashrc}}'"     # boucle sur les profils toute seule
```

L'étape n'écrit que `{{bashrc}}`, mais le script doit d'abord savoir ce que
vaut `{{profil}}`. Il déroule donc dans cet ordre.

**1.** La liste dont l'autre dépend :

```bash
$ lister_dossiers /home
/home/alice	alice
/home/bruno	bruno
/home/carole	carole
```

**2.** Puis `bashrc`, **une fois par profil**, `{{profil}}` remplacé :

```bash
$ lister_bashrc /home/alice      →  /home/alice/.bashrc
$ lister_bashrc /home/bruno      →  (rien : pas de .bashrc)
$ lister_bashrc /home/carole     →  /home/carole/.bashrc
```

À l'écran, ces appels défilent le temps de leur exécution :

```
  … lecture de la liste « profil »
  … lecture de la liste « bashrc »
  … lecture de la liste « bashrc »
  … lecture de la liste « bashrc »
```

**3.** Ce qui reste devient les itérations — trois appels, deux résultats :

```
  ↻  étape répétée — 2 itérations
      1  profil=alice · bashrc=/home/alice/.bashrc
      2  profil=carole · bashrc=/home/carole/.bashrc
```

Une liste vide n'est pas une erreur : la branche ne produit rien, les autres
continuent. Une commande qui rend un code non nul sans rien écrire compte
comme vide — `ls`, `grep` et `find` le font quand ils ne trouvent rien ; le
code est rappelé dans le message et dans le journal. Si toute l'étape se
retrouve sans itération, elle est marquée `liste vide` au récapitulatif.

### Figer une liste, voir ce qui sera demandé

```bash
./tasker.sh --list sousdossier=/home/alice,/home/bruno   # sans interroger la commande
./tasker.sh --vars                                       # les [[ ]] et {{ }} attendus, et leur source
```

Au récapitulatif, au-delà de dix itérations, seules celles qui ont mal
tourné sont détaillées, suivies de « … et N itérations réussies ».

### Les listes toutes faites

Dix fonctions sont livrées avec le script (section 7). Elles écrivent déjà
`valeur<TAB>libellé`, encaissent les noms avec espaces, apostrophes, `$` ou
`*`, laissent Ctrl-C sortir, et ne prennent jamais « rien trouvé » pour une
erreur.

| fonction | valeur · libellé |
|---|---|
| `lister_dossiers [-i] <racine> [motif...]` | chemin · nom du dossier |
| `lister_fichiers [-i] <racine> [motif...]` | chemin · nom du fichier |
| `lister_arbre [-i] <racine> [motif...]` | chemin · chemin relatif à la racine |
| `lister_recents [-i] <racine> <jours> [motif...]` | modifiés depuis N jours |
| `lister_gros [-i] <racine> <Mo> [motif...]` | fichiers de plus de N Mo |
| `lister_si_present <chemin>...` | chemin · nom, si ça existe |
| `lister_lignes [-i] <fichier> [motif...]` | une ligne utile du fichier |
| `lister_colonne <fichier> <n> [séparateur]` | colonne n · ligne entière |
| `lister_utilisateurs [uid_mini]` | dossier personnel · nom du compte |
| `lister_montages [-i] [motif...]` | point de montage · type et périphérique |

```bash
TK_LISTES=(
"journal|lister_fichiers /var/log '*.log' '*.log.1'"
"recent|lister_recents /var/log 2"
"config|lister_arbre /etc '*.conf'"
"poste|lister_colonne ./postes.csv 2"
"disque|lister_montages"
)
```

Chaque home du système, et un fichier dans chacun — les deux listes
s'emboîtent toutes seules :

```bash
TK_LISTES=(
"compte|lister_utilisateurs"
"historique|lister_si_present '{{compte}}/.bash_history'"
)
```

**Les motifs sont facultatifs, et multiples.** Ils portent sur le **nom** et
jamais sur le chemin, comme `find -name`, et **distinguent les majuscules**.

| | |
|---|---|
| `lister_fichiers /etc` | tout, fichiers cachés compris |
| `lister_fichiers /etc '*.conf'` | un motif |
| `lister_fichiers /etc '*.conf' '*.cfg'` | plusieurs |
| `lister_fichiers /etc '[!.]*'` | tout sauf les cachés |
| `lister_fichiers -i /docs '*.pdf'` | `.pdf`, `.PDF`, `.Pdf` |

Trois précautions déjà prises : `lister_arbre` ne suit pas les liens vers
des dossiers, donc aucune boucle ; un dossier illisible est signalé au
journal et sauté, sans arrêter le reste ; un nom impossible à écrire sur une
ligne (tabulation, retour à la ligne) est écarté avec un mot au journal.

Deux dépendances, et c'est tout : `lister_recents` et `lister_gros` appellent
`find` ; `lister_montages` lit `/proc/mounts`, donc Linux. Chacune le dit et
rend une liste vide si ce n'est pas là.

### Écrire la vôtre

`emettre <valeur> [libellé]` écrit une ligne et refuse ce qui casserait la
suite. C'est la seule chose à retenir, avec le test d'interruption.

```bash
lister_gros_dossiers() {          # <racine> [Mo mini, 100 par défaut]
    local d taille
    while IFS=$'\t' read -r d _; do
        (( INTERROMPU )) && return 130
        taille="$(du -sm "$d" 2>/dev/null | cut -f1)"
        (( ${taille:-0} >= ${2:-100} )) && emettre "$d" "${d##*/} — ${taille} Mo"
    done < <(lister_dossiers "$1")
    return 0
}
```

Avant de la brancher, lancez-la à la main : c'est le meilleur moyen de voir
ce que le script recevra.

```bash
$ lister_gros_dossiers /srv/data 10
/srv/data/photos	photos — 240 Mo
/srv/data/videos	videos — 1503 Mo
```

Valeurs sur la sortie standard, messages sur `>&2` — ils vont au journal.
Voir ce qui sera demandé et d'où ça vient : `./tasker.sh --vars`.

---

## Fichier de configuration `-c`

Du shell. Il fixe les variables, et peut redéfinir les commandes.

```bash
# poste.conf
DOSSIER="/srv/data"
TK_OPERATEUR="M. Dupont"
```

```bash
./tasker.sh -c poste.conf
./tasker.sh -c poste.conf -s DOSSIER=/autre     # surcharge ponctuelle
./tasker.sh -t > poste.conf                     # gabarit des variables du script
./tasker.sh -c cas.conf -t > poste2.conf        # gabarit d'un cas : « source cas.conf » + ses variables
```

Priorité : valeurs du script &lt; fichier `-c` &lt; `--set`. Un tableau (`TK_REQUIS`)
ne se change que dans le fichier, pas par `--set`. Dans le fichier,
`return` et jamais `exit` : `exit` tuerait le script, et il est refusé.

Un jeu d'étapes complet, sans copier le script :

```bash
# cas.conf
DOSSIER="/srv/data"
definir_commandes() {
    TK_COMMANDES=("Contenu|true|ls '$DOSSIER'")
    TK_LISTES=()
}
```

Un cas dérivé d'un autre :

```bash
# poste2.conf
source "$(dirname "${BASH_SOURCE[0]}")/cas.conf"
DOSSIER="/srv/autre"
```

| fichier fourni | contenu |
|---|---|
| `exemples/forensic.conf` | analyse d'une image disque : menus, listes emboîtées, fonctions |
| `exemples/pc07.conf` | `source forensic.conf` + six variables |

---

## Ce que le script attend de vous

Tout ce qui commence par `TK_` est à lui. Les autres noms sont à vous.

### Les réglages — section 2, ou votre fichier `-c`

| variable | rôle | valeurs |
|---|---|---|
| `TK_OPERATEUR` | qui a lancé, noté au bandeau, au journal et au rapport | texte ; `${SUDO_USER:-$USER}` prend la vraie personne sous sudo |
| `TK_TOUT_VALIDER` | confirmer chaque étape, même les `false` | `true` / `false` (ou `-a`) |
| `TK_MAX_ITERATIONS` | plafond d'une étape répétée, au-delà elle est tronquée | entier ≥ 1 |
| `TK_REQUIS` | binaires vérifiés au départ ; absents = avertissement | tableau : `(du df)` |
| `TK_INTRO` | texte affiché après le bandeau (facultatif) | texte, plusieurs lignes possibles |

### Dans `calculer_variables` (section 6)

Recalculée après `-c` et `--set`, pour que tout suive la dernière valeur.

| variable | rôle | exemple |
|---|---|---|
| `TK_SUJET` | titre court, en tête et au récapitulatif | `"$PC · $SALLE"` |
| `TK_DETAILS` | lignes du bandeau de départ | `("image=$IMAGE" "fuseau=$TZ")` — clé sans accent |
| `TK_PREFIX` | préfixe des fichiers écrits, sans `/` | `"${PC}_${SALLE}"` |
| `TK_DIR_LOGS` | dossier du journal, du rapport et de l'état de reprise | `"$DEST/logs"` |
| `TK_DIR_xxx` | tout autre dossier de travail : vérifié, créé au besoin | `TK_DIR_BODY`, `TK_DIR_SORTIE`… |

`TK_SUJET`, `TK_PREFIX` et `TK_DIR_LOGS` sont obligatoires : le script refuse de
partir sans.

### Les trois fonctions appelées par le script

| fonction | quand | ce qu'elle doit faire |
|---|---|---|
| `calculer_variables` | après `-c` et `--set` | poser les variables ci-dessus |
| `verifier` | avant la première étape | vos contrôles ; `return 1` arrête tout |
| `definir_commandes` | après `calculer_variables` | remplir `TK_COMMANDES` et `TK_LISTES` |

Un fichier `-c` peut remplacer n'importe laquelle des trois. S'il écrit
`TK_COMMANDES=(…)` directement, `definir_commandes` n'est pas appelée.

### Ce que vous pouvez utiliser dans vos fonctions

| nom | usage |
|---|---|
| `(( INTERROMPU )) && return 130` | en tête de toute boucle : Ctrl-C doit pouvoir en sortir |
| `erreur "…"` `attention "…"` `info "…"` | un message rouge, jaune, estompé |
| `journal "…"` | une ligne horodatée dans le journal |
| `lire "invite " variable` | poser une question (Ctrl-C et Ctrl-D y sont gérés) |
| `demander_oui_non "… ? "` | vrai sauf `n` |
| `pluriel N` | écrit `s` si N > 1 |

Dans une fonction de **liste** : les valeurs sur la sortie standard, une
par ligne ; les messages sur `>&2` — sinon ils seraient pris pour des
valeurs.

---

## Options

| option | valeur | effet |
|---|---|---|
| `-c`, `--config` | fichier | variables et commandes lues dans un fichier |
| `-s`, `--set` | `NOM=valeur` | fixer une variable des sections 1 et 2 |
| `-D`, `--var` | `nom=valeur` | répondre d'avance à `[[nom]]` |
| `--list` | `nom=a,b,c` | figer `{{nom}}` sur ces valeurs |
| `--vars` | | montrer les `[[ ]]` et `{{ }}` attendus |
| `-h`, `--help` | `TK_SUJET` | l'aide ; `etapes` `valeurs` `outils` `config` `exemple` `tout` |
| `-t`, `--template` | | écrire un fichier `-c` sur la sortie standard |
| `-l`, `--plan` | | le plan, sans rien lancer |
| `-n`, `--dry-run` | | tout afficher, rien exécuter — sauf les commandes de `TK_LISTES`, lancées pour annoncer les itérations |
| `-o`, `--only` | `2,5-7` | ne jouer que ces étapes |
| `-f`, `--from` | `4` | partir de l'étape 4 |
| `-r`, `--resume` | | sauter les étapes déjà réussies |
| `-a`, `--ask` | | confirmer chaque étape, même les `false` |
| `-y`, `--yes` | | ne rien demander |
| `--color` | `auto` `always` `never` | couleur ; `--no-color` = `never` ; la variable `NO_COLOR` est respectée |

```bash
./tasker.sh -yn                    # options combinées
./tasker.sh -o3 -cposte.conf       # valeur collée
./tasker.sh -y &                   # en arrière-plan
```

Code de sortie : `0` si tout est passé, `1` s'il reste un échec.

---

## Touches

| à une étape | |
|---|---|
| `Entrée` | exécuter |
| `p` | passer |
| `e` | éditer la commande, pour cette fois |
| `r` | ressaisir les `[[valeurs]]` |
| `q` | quitter |
| `u` | *(étape répétée)* une itération à la fois |
| `l` | *(étape répétée)* lister les itérations |

| à une question | |
|---|---|
| `1` `2` `3` | choisir |
| `Entrée` | la proposition 1 |
| `a` | autre valeur |
| `p` | passer l'étape |
| `q` | quitter |

| dans une étape répétée | |
|---|---|
| `t` | *(après `u`)* enchaîner le reste sans redemander |
| `q` | *(après `u`)* arrêter la boucle, passer à l'étape suivante |
| `Entrée` / `t` / `n` / `q` | *(après un échec)* continuer · continuer sans redemander · arrêter la boucle · quitter |

| après un échec ou une interruption | |
|---|---|
| `Continuer quand même ? [O/n]` | `Entrée` continue, `n` arrête le script |
| `Passer à l'étape suivante ? [O/n]` | après un Ctrl-C sur la commande |

| Ctrl-C, Ctrl-D | |
|---|---|
| Ctrl-C pendant une commande | l'interrompt ; le script demande si l'on continue |
| Ctrl-C pendant une question | arrête le script, avec le récapitulatif |
| Ctrl-D à une question | arrête le script : plus personne au clavier |

---

## Marques

```
  ○ à faire  ◐ en cours  ● réussie  ✗ échec  ⊘ passée  ⊗ interrompue  ◌ simulée
```

```
  ●  3  Taille de chaque sous-dossier                 3/3  1s
      ├─ ● sousdossier=documents                          0s
      └─ ✗ sousdossier=projets                        code 1
```

Les couleurs suivent une règle simple : **l'étape en cours est le seul
élément en couleur chaude** — son cercle, son numéro, sa barre. Le reste est
en retrait : les filets et la sortie des commandes sont estompés, les états
gardent leur teinte (vert réussi, rouge échoué, ambre interrompu). Une
commande qui pose ses propres couleurs reprend la main, on ne lutte pas
contre elle.

Sur un terminal 256 couleurs la palette est adoucie ; ailleurs elle retombe
sur les huit couleurs de base. Jamais de fond, jamais de gris fixe : le
retrait est l'attribut *faint*, qui suit le thème du terminal, clair ou
sombre. `--no-color`, `--color never` et `NO_COLOR` coupent tout.

---

## Ce qui est écrit

```
<TK_DIR_LOGS>/<TK_PREFIX>_script.log     chaque commande, code, durée ; s'allonge à chaque exécution
<TK_DIR_LOGS>/<TK_PREFIX>_rapport.txt    le récapitulatif, réécrit à chaque exécution
<TK_DIR_LOGS>/<TK_PREFIX>_etat.txt       les étapes réussies (pour -r)
```

`-r` reconnaît une étape à l'empreinte de son titre **et** de sa commande :
modifiez la commande, elle sera rejouée. Deux étapes identiques ont deux
empreintes.

---

## sudo, terminal, signaux

| situation | comportement |
|---|---|
| `sudo` dans une étape | mot de passe demandé au moment voulu, y compris avec `log` |
| `sudo` avec `-y` | le script prévient au départ : faites `sudo -v` avant |
| script lancé sous `sudo` | le rapport note `SUDO_USER` et « (root) » |
| programme plein écran interrompu | le terminal est rendu tel qu'il était |
| terminal fermé, `kill` | récapitulatif et journal quand même écrits |

---

## Limites

* Les commandes passent par `eval`, dans le shell du script : n'y mettez
  que les vôtres. `set -u` est actif : une variable non définie arrête
  l'étape. Un `cd` persiste jusqu'à la fin ; `set -e`, `set -x`, `IFS`, les
  options `shopt`, `LC_ALL` et les traps sont remis après chaque commande.
* `head` derrière un `tee` ferme le tube : code 141. Utilisez `tail`.
* Pas de commande interactive avec `log`.
* Une commande de `TK_LISTES` ne lit pas le clavier.
* Ctrl-C interrompt la commande en cours, pas la ligne : sur `a ; b`, `b` tourne. Écrivez `a && b`.

---

## Licence

MIT — voir [LICENSE](LICENSE). Faites-en ce que vous voulez, gardez la
mention de copyright, et c'est fourni sans garantie.
