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
./forensic.sh -c exemples/pc07.conf --image /images/autre.dd   # surcharge ponctuelle
```

Priorité : section 1 &lt; fichier `-c` &lt; options de la ligne de commande.

Prérequis : **bash 4.3+** et la Sleuth Kit / TestDisk. Un binaire manquant
n'est qu'un avertissement : on peut vouloir ne lancer qu'une partie des étapes.

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

Au-delà de deux ou trois instructions, écrivez une fonction en **section 3** et
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
| `s` | revoir la commande en clair, coupée aux espaces |
| `q` | arrêter le script |
| `u` | *(étape répétée)* exécuter une itération à la fois |
| `l` | *(étape répétée)* lister toutes les itérations prévues |

`Ctrl-C` interrompt la commande en cours sans tuer le script : il vous demande
si vous continuez.

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

---

## Limites connues

* Les commandes passent par `eval` : `>`, `|` et `sudo tee` fonctionnent, mais
  **tout est interprété par le shell**. N'y mettez que des commandes que vous
  écrivez vous-même.
* `tail` après un `tee`, oui ; `head`, non : `head` ferme le tube, la commande
  amont meurt d'un `SIGPIPE` et l'étape est comptée en échec (code 141).
* Ne mettez jamais une commande interactive dans un tube ni avec l'option `log` :
  `photorec` perdrait son terminal.
* Pas de `|` dans le titre ni dans le champ validation.
* Dans le code, tout texte affiché dans une **colonne de largeur imposée**
  (`%-10s`…) reste en ASCII : sous une locale `C`, `printf` compte les octets et
  un accent décalerait la colonne. Les libellés accentués sont toujours rejetés
  en fin de ligne.
