# forensic.sh

Un script bash qui enchaîne des commandes forensiques, **validées une à une**.

Il ne remplace ni `fls` ni `photorec` : il les met bout à bout, vous montre
chaque commande avant de la lancer, garde une trace de tout, et vous laisse
reprendre la main à n'importe quel moment.

```
────────────────────────────────────────────────────────────────
 ━━━━━━━━━━━━  [6/8] Inventaire par utilisateur
────────────────────────────────────────────────────────────────
  ↻ 3 itérations
    · home=Users/alice
    · home=Users/bob
    · home=Users/charlie
  Entrée tout exécuter · u une par une · l lister · p passer · q quitter
  >
```

---

## Commencer par la démonstration

```bash
./forensic.sh --demo
```

Un bac à sable est fabriqué dans `/tmp` et le script y rejoue **tous ses
mécanismes** — menus, étapes répétées, boucles imbriquées, journal — avec
`ls`, `wc` et `sha256sum`. Aucune image disque, aucun outil forensique,
rien à installer, rien à casser.

Les étapes de la démonstration sont dans `exemples/demo.conf`, commentées
une à une. C'est aussi un exemple complet de fichier `-c` : il fixe les
variables, définit ses propres commandes et listes, et ajoute deux
fonctions.

👉 **[TUTORIEL.md](TUTORIEL.md)** reprend tout depuis zéro, avec des
exemples exécutables.

---

## Démarrer

```bash
chmod +x forensic.sh
./forensic.sh -h              # l'aide complète
./forensic.sh --etapes        # le plan, sans rien exécuter
./forensic.sh --vars          # les valeurs qui vont être demandées
./forensic.sh -n              # simulation
./forensic.sh                 # pour de vrai
```

Deux façons de décrire un poste :

* éditer la **section 1** du script (le plus simple si vous n'avez qu'une image) ;
* écrire un petit fichier de configuration et le passer avec `-c` :

```bash
./forensic.sh -c exemples/pc07.conf
./forensic.sh -c exemples/pc07.conf --set IMAGE=/images/autre.dd   # surcharge ponctuelle
```

Priorité : section 1 &lt; fichier `-c` &lt; `--set NOM=valeur`.

Les noms des variables sont les vôtres : le script ne connaît que ce que
`calculer_variables` lui donne (`SUJET`, `DETAILS`, `PREFIX`, `DIR_xxx`) et
les contrôles que vous écrivez dans `verifier`. Rien dans la mécanique ne
parle d'image disque, de poste ni de salle.

Prérequis : **bash 4.3+** et la Sleuth Kit / TestDisk. Un binaire manquant
n'est qu'un avertissement : on peut vouloir ne lancer qu'une partie des étapes.

---

## Lire l'écran

Le plan s'affiche au démarrage, le récapitulatif à la sortie. Les deux
emploient les mêmes marques, et les itérations d'une étape répétée
apparaissent en dessous d'elle, comme des sous-tâches.

| | |
|---|---|
| `○` | à faire |
| `◐` | en cours |
| `●` | réussie |
| `✗` | échec |
| `⊘` | passée |
| `⊗` | interrompue |
| `◌` | simulée (`-n`) |

```
────────────────────────────────────────────────────────────
 Récapitulatif   PC07 · B204 · windows
────────────────────────────────────────────────────────────
  ●  1  Table des partitions                            0s
  ●  2  Fichiers alloués et supprimés                   4s
  ⊘  3  Inodes non alloués                          passee
  ●  4  Fusion des body files                           0s
  ●  6  Inventaire par utilisateur                 3/3  4s
      ├─ ● home=Users/alice                             1s
      ├─ ● home=Users/bruno                             2s
      └─ ✗ home=Users/celia                        code 1
────────────────────────────────────────────────────────────
  4 réussies · 1 en échec · 1 passée · total 9s
```

Les titres accentués sont alignés correctement même sous une locale
`POSIX`, où `printf` compte les octets : le script mesure la largeur
réelle des chaînes (`largeur_texte`).

---

## Ajouter une étape

Une ligne dans le tableau `COMMANDES`, section 2 :

```bash
"Titre|validation|commande"
```

| champ | rôle |
|---|---|
| `Titre` | ce qui s'affiche et ce qui apparaît au récapitulatif |
| `validation` | `true` = demander avant de lancer, `false` = lancer directement |
| `commande` | n'importe quelle commande shell : tubes, redirections, tests |

Le champ `validation` accepte des options, séparées par des virgules :

| option | effet |
|---|---|
| `log` | la sortie de la commande est recopiée dans le journal |
| `stop` | un échec arrête le script, sans question |
| `continu` | un échec est ignoré, sans question |

```bash
"Table des partitions|true,log|mmls '$IMAGE'"
"Inodes non alloués|true,continu|ils -m -o [[offset]] '$IMAGE' > '$DIR_BODY/x.body'"
```

Le découpage se fait sur les **deux premiers `|`** seulement : les tubes de la
commande sont préservés, mais le titre ne peut pas contenir de `|`.

---

## Trois façons d'insérer une valeur

### `$VARIABLE` — connue à l'avance

Remplacée au lancement. `$IMAGE`, `$DIR_BODY`, `$PREFIX`…

⚠️ Le tableau est entre guillemets doubles : une variable née **pendant** la
commande doit être échappée, sinon `set -u` arrête tout.

```bash
FAUX   "Boucle|true|for u in a b; do echo home_$u; done"
JUSTE  "Boucle|true|for u in a b; do echo home_\$u; done"
```

Idem pour `\$(date)`, `\$1`, `\$?`.

### `[[nom]]` — une valeur, demandée une fois

Demandée quand on arrive sur l'étape, puis **réutilisée** partout où le même
`[[nom]]` apparaît. `[[offset]]` est saisi une fois et servi à `fls` comme à `ils`.

Si le tableau `LISTES` contient une entrée du même nom, la question devient un
**menu numéroté** — plus de chiffre recopié à la main :

```
    ┌ [[offset]] — 2 propositions
    │  1  2048           NTFS / exFAT (0x07) — 40.0 Go
    │  2  83884032       Linux (0x83) — 10.0 Go
    │  a  saisir une autre valeur
    └ choix [1] :
```

Pré-remplissable : `--var offset=2048` (répétable), `--vars` pour voir les noms attendus.

### `{{nom}}` — plusieurs valeurs, l'étape est répétée

C'est le mécanisme des traitements récursifs. Les valeurs viennent de `LISTES` :

```bash
LISTES=(
  "home|lister_homes '$IMAGE' '[[offset]]' '$OS'"
  "fichier|lister_fichiers '$IMAGE' '[[offset]]' '{{home}}'"
)
```

```bash
# une itération par profil utilisateur
"Inventaire|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' '{{home_libelle}}' '$DIR_BODY'"

# une itération par fichier de chaque profil : la boucle sur les homes
# se déclenche toute seule, parce que la liste "fichier" en dépend
"Hachage|true|hacher_fichier '$IMAGE' '[[offset]]' '{{fichier}}' '{{fichier_libelle}}' >> '$DIR_LOGS/h.txt'"
```

Trois choses à retenir :

* **Emboîtement automatique.** Une liste qui en appelle une autre déclenche la
  boucle extérieure : vous n'écrivez que la liste qui vous intéresse.
  Deux `{{listes}}` écrites côte à côte s'emboîtent de gauche à droite.
* **Valeur et libellé.** Une ligne de liste peut s'écrire
  `valeur<TAB>libellé` : seule la valeur entre dans la commande, le libellé
  s'affiche. Il reste accessible sous `{{nom_libelle}}`. Pour `home`, la valeur
  est l'inode (ce qu'attend `fls`) et le libellé le chemin (ce que vous lisez).
* **Toujours entre apostrophes** : `'{{fichier}}'`. Les valeurs viennent d'un
  programme et contiennent des espaces ; le script neutralise les apostrophes
  qu'elles pourraient contenir, à condition que le placeholder soit quoté.

Un garde-fou (`MAX_ITERATIONS`, section 1) évite de lancer trois mille commandes
par inadvertance, et le nombre d'itérations est toujours annoncé **avant**
validation.

Pour figer une liste sans l'interroger : `--liste home=41-144-1,52-144-1`.

---

## Écrire une fonction plutôt qu'une ligne à rallonge

Au-delà de deux ou trois instructions, écrivez une fonction en **section 4** et
appelez-la depuis le tableau. Plus d'échappements à gérer, et la ligne reste
lisible à l'affichage.

```bash
mon_traitement() {
    local racine="$1"
    local f
    for f in "$racine"/*; do
        (( INTERROMPU )) && return 130     # sans ça, Ctrl-C ne sort pas de la boucle
        traiter "$f" || return 1
    done
    return 0                                # ce code devient ✅ ou ❌
}
```

Une fonction de **liste** écrit une valeur par ligne sur sa sortie standard
(et ses messages d'erreur sur `>&2`, sinon ils seraient pris pour des valeurs).

---

## Pendant l'exécution

| touche | effet |
|---|---|
| `Entrée` | exécuter |
| `p` | passer cette étape |
| `e` | éditer la ligne pour cette exécution seulement |
| `r` | ressaisir les `[[valeurs]]` de l'étape |
| `q` | arrêter le script |
| `u` | *(étape répétée)* exécuter une itération à la fois |
| `l` | *(étape répétée)* lister toutes les itérations prévues |

### Ctrl-C, Ctrl-D

| quand | ce qui se passe |
|---|---|
| pendant une **commande** | la commande est interrompue, **pas** le script ; il vous demande si vous continuez avec la suivante |
| pendant une **question** | arrêt propre, avec le récapitulatif et le rapport |
| `Ctrl-D` à une question | plus personne au clavier : arrêt, plutôt qu'une réponse inventée |

Attention : Ctrl-C interrompt **la commande en cours**, pas la ligne
entière. Sur une étape `a ; b`, `b` s'exécutera quand même — écrivez
`a && b` si ce n'est pas ce que vous voulez. Et dans une boucle de vos
propres fonctions, mettez `(( INTERROMPU )) && return 130` en première
ligne.

### À une question de valeur

| touche | effet |
|---|---|
| `1` `2` `3` | choisir dans le menu |
| `Entrée` | prendre la proposition 1 |
| `a` | saisir une autre valeur |
| `p` | passer cette étape |
| `q` | quitter le script |

Après un `a`, `p` et `q` redeviennent des valeurs ordinaires.

---

## Reprendre, filtrer, rejouer

```bash
./forensic.sh --reprendre         # saute les étapes déjà réussies
./forensic.sh --seulement 2,5-7   # ne joue que celles-là
./forensic.sh --depuis 4          # repart de l'étape 4
./forensic.sh -v                  # confirme chaque étape, même les false
./forensic.sh -y                  # ne demande jamais rien
```

`--reprendre` s'appuie sur l'empreinte du titre **et** de la commande : modifiez
la commande, l'étape sera rejouée.

Code de sortie : `0` si tout est passé, `1` s'il reste un échec.

---

## Ce qui est écrit sur le disque

```
<BASE>/<SALLE>/<OS>/<PC>/
├── body/       les body files (fls, ils, fusion, un par profil)
├── timeline/   la timeline mactime
├── carving/    la récupération photorec
└── logs/
    ├── <prefixe>_script.log     chaque commande, son code, sa durée
    ├── <prefixe>_rapport.txt    le récapitulatif, poste et analyste inclus
    └── <prefixe>_etat.txt       les étapes réussies (pour --reprendre)
```

Toute variable nommée `DIR_quelquechose` est vue comme un dossier de travail :
le script la vérifie et la crée au besoin. En ajouter un ne demande rien d'autre
que de l'écrire dans `calculer_chemins`.

## Organisation du script

| section | contenu | on y touche |
|---|---|---|
| 1 | variables : image, poste, fuseau… | à chaque analyse |
| 2 | `COMMANDES` : les étapes | souvent |
| 3 | `LISTES` : d'où viennent `[[valeurs]]` et `{{listes}}` | avec les commandes |
| 4 | fonctions : vos traitements | parfois |
| 5 | mécanique | jamais |

Un fichier `-c` peut redéfinir `definir_commandes` et ajouter des fonctions :
`exemples/demo.conf` le fait, ce qui permet d'avoir un jeu d'étapes par type
d'analyse sans copier le script.

---

## Sans image sous la main

```
$ ./forensic.sh
✗  image absente : /images/pc07.dd
   réglez IMAGE en section 1, ou : --set IMAGE=/chemin.dd · -c poste.conf · --demo pour essayer sans image
```

## Limites connues

* Les commandes passent par `eval` : `>`, `|` et `sudo tee` fonctionnent, mais
  **tout est interprété par le shell**. N'y mettez que des commandes que vous
  écrivez vous-même.
* `tail` après un `tee`, oui ; `head`, non : `head` ferme le tube, la commande
  amont meurt d'un `SIGPIPE` et l'étape est comptée en échec (code 141).
* Ne mettez jamais une commande interactive dans un tube ni avec l'option `log` :
  `photorec` perdrait son terminal.
* Pas de `|` dans le titre ni dans le champ validation.
* Ctrl-C n'interrompt pas un `read` simplement piégé : bash exécute le
  gestionnaire puis retourne attendre. Le script traite donc les deux
  situations séparément (`EN_SAISIE`), sans quoi une question paraîtrait
  figée après un `^C`.
* Dans le code, tout texte affiché dans une **colonne de largeur imposée**
  (`%-10s`…) reste en ASCII : sous une locale `C`, `printf` compte les octets et
  un accent décalerait la colonne. Les libellés accentués sont toujours rejetés
  en fin de ligne.
