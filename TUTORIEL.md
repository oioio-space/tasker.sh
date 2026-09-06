# tasker.sh — le cas forensique, pas à pas

On a une image disque, `pc07.dd`. On veut sa table des partitions, une
timeline des fichiers, un inventaire par utilisateur, et récupérer les
fichiers effacés. Ce document déroule `exemples/forensic.conf` ligne à
ligne : ce qu'on tape, ce qui s'affiche, et pourquoi c'est écrit ainsi.

Tout ce qui est expliqué ici vaut pour n'importe quel autre usage du
script : seules les commandes changent.

---

## 1. Lancer

```bash
./tasker.sh -c exemples/pc07.conf
```

`pc07.conf` tient en huit lignes : il hérite du cas complet, puis règle
son poste.

```bash
source "$(dirname "${BASH_SOURCE[0]}")/forensic.conf"

IMAGE="/images/pc07.dd"
PC="PC07"
SALLE="B204"
OS="windows"
BASE="/cases"
TK_OPERATEUR="M. Dupont"
TZ_MACTIME="Europe/Paris"
```

Pour un nouveau poste, on ne réécrit rien :

```bash
./tasker.sh -c exemples/forensic.conf -t > pc09.conf    # gabarit pré-rempli
# éditer IMAGE, PC, SALLE, OS
./tasker.sh -c pc09.conf
```

---

## 2. Ce qui s'affiche

### Le bandeau et le plan

```
 tasker.sh  PC07 · B204 · windows
────────────────────────────────────────────────────────────
  image      /images/pc07.dd
  sortie     /cases/B204/windows/PC07
  fuseau     Europe/Paris
  par        M. Dupont
  journal    /cases/B204/windows/PC07/logs/PC07_B204_windows_script.log

 Plan   8 étapes
────────────────────────────────────────────────────────────
  ○  1  Table des partitions                              log
  ○  2  Fichiers alloués et supprimés
  ○  3  Inodes non alloués                                continu
  ○  4  Fusion des body files                             auto
  ○  5  Timeline
  ○  6  Inventaire par utilisateur                        ↻ répétée
  ○  7  Liste des partitions (testdisk)                   log
  ○  8  Carving
```

On sait d'un coup d'œil ce qui va se passer. `auto` = partira sans
demander ; `↻ répétée` = une fois par valeur d'une liste ; `log` = sortie
recopiée au journal.

### Étape 1 : une commande simple

```
  ◐ 1/8  ━━━━━━━━━━━━  Table des partitions
────────────────────────────────────────────────────────────
  $ mmls '/images/pc07.dd'
  Entrée exécuter · p passer · e éditer · r ressaisir · q quitter
  › 
```

La commande est affichée **avant** de partir. `Entrée` la lance :

```
      Slot      Start        End          Length       Description
002:  000:000   0000002048   0083884031   0083881984   NTFS / exFAT (0x07)
  ●  terminée en 0s
```

### Étape 2 : une valeur demandée, proposée en menu

`fls` a besoin de l'offset de la partition, celui que `mmls` vient
d'afficher. Plutôt que de le recopier, le script le propose :

```
  ◐ 2/8  ━━━━━━━━━━━━  Fichiers alloués et supprimés
────────────────────────────────────────────────────────────
    ┌─ [[offset]]  — utilisé aux étapes 2, 3, 6 et par la liste home
    │
    │   1  2048           NTFS / exFAT (0x07) — 40.0 Go
    │
    │   a  saisir une autre valeur
    │   p  passer cette étape
    │   q  quitter le script
    └─ votre choix [1] › 
    → 2048

  $ fls -r -p -m / -o 2048 '/images/pc07.dd' > '/cases/B204/windows/PC07/body/PC07_B204_windows_fls.body'
```

`[[offset]]` est demandé **une fois**. Les étapes 3 et 6, et la liste des
profils, le réutiliseront sans rien redemander.

### Étape 6 : une étape rejouée par profil

```
  ◐ 6/8  ━━━━━━━━━━━━  Inventaire par utilisateur
────────────────────────────────────────────────────────────
  ↻  étape répétée — 3 itérations
      1  home=Users/alice
      2  home=Users/bruno
      3  home=Users/celia
  Entrée tout exécuter · u une par une · l lister · p passer · e éditer · r ressaisir · q quitter
  › 
```

Le nombre d'itérations est annoncé **avant** de lancer quoi que ce soit.
`l` montre les trois commandes en entier ; `u` les déroule une par une.

```
  ── 1/3 ── home=Users/alice
     $ inventorier_home '/images/pc07.dd' '2048' '51-144-1' 'Users/alice' '/cases/B204/windows/PC07/body'
  142 entrées -> /cases/B204/windows/PC07/body/home_Users_alice.body
  ●  terminée en 1s
```

### Le récapitulatif

```
 Récapitulatif   PC07 · B204 · windows
────────────────────────────────────────────────────────────
  ●  1  Table des partitions                              0s
  ●  2  Fichiers alloués et supprimés                     4s
  ✗  3  Inodes non alloués                            code 1
  ●  4  Fusion des body files                             0s
  ●  5  Timeline                                          2s
  ●  6  Inventaire par utilisateur                   3/3  3s
      ├─ ● home=Users/alice                                1s
      ├─ ● home=Users/bruno                                1s
      └─ ● home=Users/celia                                1s
  ●  7  Liste des partitions (testdisk)                   0s
  ●  8  Carving                                        1h04m
────────────────────────────────────────────────────────────
  7 réussies · 1 en échec · 0 passée · total 1h14m
  journal  /cases/B204/windows/PC07/logs/PC07_B204_windows_script.log
  rapport  /cases/B204/windows/PC07/logs/PC07_B204_windows_rapport.txt
```

L'étape 3 a échoué : c'est normal, `ils` échoue sur NTFS, et l'étape
était marquée `continu` — le script n'a rien demandé et a poursuivi. Le
rapport écrit sur disque contient la même chose, en texte brut.

---

## 3. `forensic.conf`, ligne à ligne

### Les variables

```bash
IMAGE="/images/pc07.dd"        # image disque à analyser
PC="PC07"                      # poste
SALLE="B204"                   # salle
OS="windows"                   # windows ou linux
BASE="/cases"                  # racine où tout est écrit
TK_OPERATEUR="${SUDO_USER:-${USER:-inconnu}}"
TZ_MACTIME="Europe/Paris"      # fuseau du POSTE ANALYSÉ
TK_REQUIS=(mmls fls ils icat mactime testdisk photorec)
```

`IMAGE`, `PC`, `SALLE`, `OS`, `BASE`, `TZ_MACTIME` sont des noms choisis
ici : le script ne les connaît pas. Ceux qui commencent par `TK_` sont à
lui — `TK_REQUIS` est vérifié au départ ; un binaire absent n'est qu'un
avertissement, car on peut ne jouer qu'une partie des étapes.

`TZ_MACTIME` : le fuseau du poste analysé, pas le vôtre, sinon la
timeline ne correspondra ni aux journaux applicatifs ni aux témoignages.
Un **nom de zone** (`Europe/Paris`), jamais un décalage (`UTC+1`) qui
serait faux la moitié de l'année.

### Ce que le script attend

```bash
calculer_variables() {
    TK_SUJET="$PC · $SALLE · $OS"                       # en tête et au récapitulatif
    TK_DETAILS=("image=$IMAGE" "fuseau=$TZ_MACTIME")    # lignes du bandeau
    TK_PREFIX="${PC}_${SALLE}_${OS}"                    # préfixe des fichiers écrits
    DEST="$BASE/$SALLE/$OS/$PC"
    DIR_BODY="$DEST/body"                            # DIR_xxx : créés au besoin
    DIR_TIMELINE="$DEST/timeline"
    DIR_CARVING="$DEST/carving"
    DIR_LOGS="$DEST/logs"                            # journal, rapport, état
}
```

Trois noms sont obligatoires : `TK_SUJET`, `TK_PREFIX`, `DIR_LOGS` — le
script refuse de partir sans. `TK_DETAILS` est facultative. Tout
`DIR_xxx` est vérifié et créé. C'est une fonction, et pas des
affectations en vrac, pour être **recalculée après** `-c` et `--set`.

```bash
verifier() {
    [[ -e "$IMAGE" ]] || { erreur "image absente : $IMAGE"; return 1; }
    [[ -r "$IMAGE" ]] || { erreur "image illisible : $IMAGE"; return 1; }
    return 0
}
```

Vos contrôles de départ. `return 1` arrête tout avant la première étape.

### Les commandes

```bash
"Table des partitions|true,log|mmls '$IMAGE'"
```
`log` : la table est recopiée au journal, on la retrouvera.

```bash
"Fichiers alloués et supprimés|true|fls -r -p -m / -o '[[offset]]' '$IMAGE' > '$DIR_BODY/${TK_PREFIX}_fls.body'"
```
`-r` récursif, `-p` chemins complets, `-m /` format *body* pour
`mactime`. `[[offset]]` : demandé ici, réutilisé ensuite. `'$IMAGE'`
entre apostrophes : le chemin peut contenir des espaces.

```bash
"Inodes non alloués|true,continu|ils -m -o '[[offset]]' '$IMAGE' > '$DIR_BODY/${TK_PREFIX}_ils.body'"
```
`continu` : `ils` échoue souvent sur NTFS ; on ne veut pas de question.

```bash
"Fusion des body files|false|fusionner_body '$DIR_BODY/${TK_PREFIX}_full.body' '$DIR_BODY/${TK_PREFIX}_fls.body' '$DIR_BODY/${TK_PREFIX}_ils.body'"
```
`false` : pas de validation, c'est une concaténation. `fusionner_body`
est une fonction du fichier : `cat` échouerait sur le body absent d'`ils`.

```bash
"Timeline|true|mactime -b '$DIR_BODY/${TK_PREFIX}_full.body' -z '$TZ_MACTIME' -d -y > '$DIR_TIMELINE/${TK_PREFIX}_timeline.csv'"
```

```bash
"Inventaire par utilisateur|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' '{{home_libelle}}' '$DIR_BODY'"
```
`{{home}}` : rejouée pour chaque profil. La liste `home` renvoie
`inode<TAB>chemin` — `{{home}}` vaut l'inode (ce que `fls` attend),
`{{home_libelle}}` le chemin (ce que vous lisez, et le nom du fichier
produit).

```bash
"Carving|true|photorec /log /logname '$DIR_LOGS/${TK_PREFIX}_photorec.log' /d '$DIR_CARVING/recup_' /cmd '$IMAGE' '[[index_testdisk]]',fileopt,everything,enable,freespace,search"
```
`photorec` veut le **numéro** de partition selon `testdisk`, pas l'offset :
d'où une seconde valeur, `[[index_testdisk]]`, avec son propre menu.
`freespace` : espace non alloué seulement ; `search` reste en dernier.
Pas d'option `log` : `photorec` est plein écran et a besoin du terminal.

### Les listes

```bash
"offset|lister_partitions '$IMAGE'"
"index_testdisk|lister_partitions_testdisk '$IMAGE'"
"home|lister_homes '$IMAGE' '[[offset]]' '$OS'"
"fichier|lister_fichiers_image '$IMAGE' '[[offset]]' '{{home}}'"
```

* `offset` et `index_testdisk` : portent le même nom que les `[[valeurs]]`
  → les questions deviennent des menus.
* `home` : utilisée en `{{home}}` → l'étape 6 est rejouée. Elle contient
  `[[offset]]` : la question est posée une fois pour toutes.
* `fichier` : contient `{{home}}` → elle est régénérée pour chaque profil.
  Écrire `{{fichier}}` seul dans une commande boucle donc sur tous les
  fichiers de tous les profils.

Une fonction de liste écrit **une valeur par ligne**, `valeur<TAB>libellé`.
Pour comprendre ce qui devient un menu ou une répétition, le plus simple est
de lancer la fonction à la main : ce qu'elle affiche est exactement ce que le
script reçoit.

`lister_partitions` lit `mmls` :

```
$ mmls '/images/pc07.dd'
DOS Partition Table
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0083884031   0083881984   NTFS / exFAT (0x07)
```

et n'en garde que deux colonnes, séparées par une tabulation :

```
$ lister_partitions '/images/pc07.dd'
2048	NTFS / exFAT (0x07) — 40.0 Go
```

Une ligne, donc une entrée. Comme la liste s'appelle `offset` et qu'une
commande écrit `[[offset]]`, cette ligne devient le menu de l'étape 2 :

```
    │   1  2048           NTFS / exFAT (0x07) — 40.0 Go
```

`2048` part dans la commande, `NTFS / exFAT (0x07) — 40.0 Go` ne sert qu'à
lire le menu.

`lister_homes` fonctionne pareil, mais elle est appelée en `{{home}}` :

```
$ lister_homes '/images/pc07.dd' 2048 windows
51-144-1	Users/alice
51-208-1	Users/bruno
51-272-1	Users/celia
```

Trois lignes, donc trois itérations à l'étape 6 — et la différence
valeur/libellé prend tout son sens : `{{home}}` vaut l'inode `51-144-1`, que
seul `fls` sait lire, et `{{home_libelle}}` vaut `Users/alice`, qui nomme le
fichier de sortie et s'affiche à l'écran.

```
  ↻  étape répétée — 3 itérations
      1  home=Users/alice
      2  home=Users/bruno
      3  home=Users/celia
```

---

## 4. Ajouter une étape : le `.bashrc` de chaque utilisateur

Les deux lignes sont dans `forensic.conf`, en commentaire. Décommentez :

```bash
"bashrc|lister_fichiers_nommes '$IMAGE' '[[offset]]' '{{home}}' '^\.bashrc$'"
```

```bash
"Contenu de chaque .bashrc|true,log|echo '--- {{bashrc_libelle}}'; icat -o '[[offset]]' '$IMAGE' '{{bashrc}}'"
```

La liste `bashrc` dépend de `{{home}}` ; l'étape n'écrit que `{{bashrc}}`.
Le script résout donc `home` d'abord, puis relance `bashrc` **une fois par
profil**, `{{home}}` remplacé par l'inode du profil en cours :

```
$ lister_fichiers_nommes '/images/pc07.dd' 2048 51-144-1 '^\.bashrc$'
51-145-3	Users/alice/.bashrc
$ lister_fichiers_nommes '/images/pc07.dd' 2048 51-208-1 '^\.bashrc$'
                                                    ← rien, bruno n'en a pas
$ lister_fichiers_nommes '/images/pc07.dd' 2048 51-272-1 '^\.bashrc$'
51-273-3	Users/celia/.bashrc
```

Trois appels, deux résultats : la branche de bruno ne produit rien et
disparaît, sans erreur ni itération vide.

```
  ↻  étape répétée — 2 itérations
      1  home=Users/alice · bashrc=Users/alice/.bashrc
      2  home=Users/celia · bashrc=Users/celia/.bashrc
```

Pour un autre fichier : changez le motif. `'^\.ssh$'`, `'\.(bash|zsh)rc$'`.

---

## 5. Quand ça se passe mal

**Une étape échoue** — le script demande :

```
  ✗  échec — code 1, 0s
  Continuer quand même ? [O/n]
```

**Ctrl-C pendant `photorec`** — la commande est interrompue, pas le
script, et le terminal est rendu tel qu'il était :

```
  ⊗  interrompu au bout de 12m30s
  Passer à l'étape suivante ? [O/n]
```

**Aucun profil n'a de `.bashrc`** — plus rien à faire pour l'étape :

```
  ⚠  la liste « bashrc » n'a renvoyé aucune valeur (code 1)
✗  les listes de cette étape n'ont rien donné : rien à exécuter.
```

Le code entre parenthèses est celui de la commande de la liste : `ls`,
`grep` et `find` rendent 1 ou 2 quand ils ne trouvent rien, et le script le
lit comme « aucune valeur », pas comme une panne. Vérifiez d'abord l'offset.
Un seul profil sans `.bashrc` ne fait pas ça — seule sa branche disparaît,
comme au § 4.

**La session SSH tombe au milieu du carving** — le rapport et le journal
sont quand même écrits, avec la raison. Le lendemain :

```bash
./tasker.sh -c pc07.conf -r        # saute ce qui a réussi, rejoue le reste
```

**Rejouer une seule étape** :

```bash
./tasker.sh -c pc07.conf -o 5 -D offset=2048
```

**Tout enchaîner sans question**, pour un poste dont on connaît déjà les
valeurs :

```bash
./tasker.sh -c pc07.conf -y -D offset=2048 -D index_testdisk=1
```

---

## 6. Porter un script existant

Le cas typique : un script de collecte, écrit un jour de hâte, qu'on
voudrait rejouer proprement, avec validation et journal.

### Avant

```bash
#!/bin/bash
OUT=/tmp/collecte
mkdir -p $OUT
hostname > $OUT/hostname.txt
cat /etc/os-release > $OUT/os-release.txt
for h in /home/*; do
    u=$(basename $h)
    ls -la $h > $OUT/ls_$u.txt
    cp $h/.bash_history $OUT/history_$u.txt 2>/dev/null
done
```

### Après : `collecte.conf`

```bash
# ./tasker.sh -c collecte.conf
OUT="/tmp/collecte"
HOMES="/home"

calculer_variables() {
    TK_SUJET="collecte $(hostname)"
    TK_DETAILS=("homes=$HOMES")
    TK_PREFIX="collecte"
    DIR_OUT="$OUT"                 # DIR_xxx : créé au besoin — le mkdir disparaît
    DIR_LOGS="$OUT/logs"
}
verifier() { [[ -d "$HOMES" ]] || { erreur "pas de $HOMES"; return 1; }; return 0; }

definir_commandes() {
TK_COMMANDES=(
"Nom de la machine|false|hostname > '$DIR_OUT/hostname.txt'"
"Version du système|false|cat /etc/os-release > '$DIR_OUT/os-release.txt'"
"Contenu de chaque home|true|ls -la '{{home}}' > '$DIR_OUT/ls_{{home_libelle}}.txt'"
"Historique de chaque home|true|cp '{{historique}}' '$DIR_OUT/history_{{home_libelle}}.txt'"
)
TK_LISTES=(
"home|lister_dossiers '$HOMES'"
"historique|lister_si_present '{{home}}/.bash_history'"
)
}
```

`lister_dossiers` et `lister_si_present` sont fournies par le script
(section 7) : rien à écrire. Ce qui a changé, ligne par ligne :

| avant | après | pourquoi |
|---|---|---|
| `OUT=/tmp/collecte` | `OUT="/tmp/collecte"` en tête | même chose, mais `-s OUT=/ailleurs` marche |
| `mkdir -p $OUT` | `DIR_OUT="$OUT"` | tout `DIR_xxx` est créé au besoin |
| `hostname > $OUT/…` | `"Nom de la machine\|false\|hostname > …"` | une ligne = une étape ; `false` : rien à valider |
| `for h in /home/*` | liste `home` + `{{home}}` | l'étape est rejouée par home, on voit combien avant de lancer |
| `u=$(basename $h)` | `{{home_libelle}}` | le libellé de la liste, c'est le nom seul |
| `cp … 2>/dev/null` | liste `historique` qui ne renvoie que ce qui existe | l'absence n'est plus un échec masqué, c'est zéro itération |
| `$h` sans guillemets | `'{{home}}'` | un home avec un espace ne casse plus rien |

### Ce que ça donne

```
  ○  1  Nom de la machine                                  auto
  ○  2  Version du système                                 auto
  ○  3  Contenu de chaque home                             ↻ répétée
  ○  4  Historique de chaque home                          ↻ répétée
```

Les deux listes lancées à la main — c'est ce que le script voit avant
d'annoncer quoi que ce soit :

```
$ lister_dossiers /home
/home/alice	alice
/home/bruno	bruno
/home/celia	celia

$ lister_si_present /home/alice/.bash_history
/home/alice/.bash_history	.bash_history
$ lister_si_present /home/bruno/.bash_history
                                          ← rien, le fichier n'existe pas
$ lister_si_present /home/celia/.bash_history
/home/celia/.bash_history	.bash_history
```

Trois homes, trois appels, deux résultats : bruno n'apparaît pas, et rien
n'a échoué — c'est ce que faisait le `2>/dev/null` de l'ancien script, en
silence.

```
  ◐ 4/4  ━━━━━━━━━━━━  Historique de chaque home
  ↻  étape répétée — 2 itérations
      1  home=alice · historique=.bash_history
      2  home=celia · historique=.bash_history
```

### Les règles quand on reprend une fonction d'un autre script

* `exit` → `return` : `exit` tuerait tasker.sh tout entier.
* Un `return` explicite à la fin : son code fait ● ou ✗.
* Variables internes en `local`.
* Dans toute boucle longue : `(( INTERROMPU )) && return 130`, sinon
  Ctrl-C tue l'itération en cours mais pas la boucle.
* `set -u` est actif : une variable non définie arrête l'étape — ce que
  l'ancien script tolérait peut-être en silence.
* Une fonction de **liste** écrit ses valeurs sur la sortie standard et
  ses messages sur `>&2`, sinon ils seraient pris pour des valeurs.

---

## 7. Ce que vous pouvez retenir pour un autre usage

Rien ici n'est propre au forensique. Le même fichier `-c` peut décrire une
sauvegarde, une batterie de tests, une installation. Ce qu'il faut :

1. des variables en tête ;
2. `calculer_variables` qui pose `TK_SUJET`, `TK_DETAILS`, `TK_PREFIX`, `DIR_LOGS` ;
3. `verifier` pour les contrôles de départ ;
4. `definir_commandes` avec `TK_COMMANDES` et `TK_LISTES` ;
5. vos fonctions.

`./tasker.sh -t > mon-cas.conf` écrit le squelette des variables ; le § 3
montre le reste sur un cas complet.

Et sur une machine où ce tutoriel n'est pas installé, le script se raconte
tout seul : `-h etapes`, `-h valeurs`, `-h outils`, `-h config`,
`-h exemple`, ou `-h tout`.
