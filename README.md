# tasker.sh

Un script bash qui enchaîne des commandes, **validées une à une**. Il ne
fait rien lui-même : il met vos commandes bout à bout, vous montre chacune
avant de la lancer, garde une trace de tout, et vous laisse reprendre la
main à n'importe quel moment.

```
────────────────────────────────────────────────────────
  ◐ 3/4  ━━━━━━━━━━━━  Taille de chaque sous-dossier
────────────────────────────────────────────────────────
  ↻  étape répétée — 3 itérations
      1  sousdossier=documents
      2  sousdossier=images
      3  sousdossier=projets
  Entrée tout exécuter · u une par une · l lister · p passer · q quitter
  ›
```

Un tableau de commandes, deux façons d'y insérer une valeur inconnue
d'avance, et un journal. Tout le reste est du confort.

---

## Commencer

```bash
./tasker.sh --demo      # un bac à sable dans /tmp, rien à installer
./tasker.sh -h          # l'aide, en 34 lignes
./tasker.sh -l          # le plan de l'exemple fourni, sans rien lancer
./tasker.sh             # l'exemple fourni : quelques commandes sur $HOME
```

👉 **[TUTORIEL.md](TUTORIEL.md)** reprend tout depuis zéro, exemples exécutables à l'appui.

Prérequis : bash 4.3 ou plus. Rien d'autre que ce que vos commandes demandent.

---

## Le script en cinq sections

| section | contenu | on y touche |
|---|---|---|
| 1 | variables : ce qui change d'une exécution à l'autre | à chaque fois |
| 2 | `COMMANDES` : les étapes, dans l'ordre | souvent |
| 3 | `LISTES` : d'où viennent les `[[valeurs]]` et les `{{listes}}` | avec les commandes |
| 4 | chemins, titre, contrôles de départ | à l'installation |
| 5 | vos fonctions | parfois |
| 6 | mécanique | jamais |

Les sections 1 à 3 tiennent dans le premier écran. Le script est livré
avec un petit exemple qui tourne partout (espace disque, contenu d'un
dossier, taille de chaque sous-dossier) ; remplacez-le, ou laissez-le et
mettez le vôtre dans un fichier de configuration.

---

## Une étape

```bash
"Titre|validation|commande"
```

| champ | rôle |
|---|---|
| `Titre` | ce qui s'affiche et ce qui apparaît au récapitulatif |
| `validation` | `true` = demander avant de lancer, `false` = lancer directement |
| `commande` | n'importe quelle commande shell : tubes, redirections, tests, fonctions de la section 5 |

Après `true` ou `false`, des options séparées par des virgules :

| option | effet |
|---|---|
| `log` | la sortie de la commande est recopiée dans le journal |
| `continu` | un échec est ignoré, sans question |
| `stop` | un échec arrête tout, sans question |

Le découpage se fait sur les **deux premiers `|`** : les tubes de la
commande sont préservés, mais le titre ne peut pas en contenir.

---

## Trois façons d'insérer une valeur

**`$VARIABLE`** — connue à l'avance, remplacée au lancement. Une variable
née *pendant* la commande s'échappe : `for f in *; do echo \$f; done`.

**`[[nom]]`** — demandée quand on arrive sur la première étape qui
l'utilise, puis réutilisée partout. Si `LISTES` contient une entrée du
même nom, la question devient un menu numéroté :

```
    ┌─ [[profondeur]]  — utilisé à l'étape 4
    │
    │   1  1              ce dossier seulement
    │   2  2              et ses sous-dossiers
    │   3  4              quatre niveaux
    │
    │   a  saisir une autre valeur
    │   p  passer cette étape
    │   q  quitter le script
    └─ votre choix [1] ›
```

**`{{nom}}`** — l'étape est rejouée pour chaque valeur de la liste
`nom`. Deux listes s'emboîtent ; une liste qui en utilise une autre
déclenche la boucle extérieure toute seule. Toujours entre apostrophes :
`'{{nom}}'`. Le libellé d'une valeur est dans `{{nom_libelle}}`.

Une liste, c'est une commande qui écrit **une valeur par ligne**,
éventuellement `valeur<TAB>libellé` :

```bash
lister_dossiers() {
    local d
    for d in "$1"/*/; do
        (( INTERROMPU )) && return 130
        [[ -d "$d" ]] || continue
        d="${d%/}"; printf '%s\t%s\n' "$d" "${d##*/}"
    done
    return 0
}
```

---

## Fichiers de configuration

Un fichier `-c` est du shell. Il peut fixer les variables de la section 1,
mais aussi redéfinir `calculer_variables`, `verifier`, `definir_commandes`
et ajouter des fonctions : c'est un jeu d'étapes complet, sans copier le
script.

```bash
./tasker.sh -t > mon-cas.conf                     # gabarit des variables de la section 1
./tasker.sh -c exemples/forensic.conf -t > pc09.conf   # gabarit d'un cas existant, pré-rempli
./tasker.sh -c pc09.conf
./tasker.sh -c pc09.conf -s IMAGE=/images/autre.dd    # surcharge ponctuelle
```

Priorité : section 1 &lt; fichier `-c` &lt; `--set NOM=valeur`.

Le script ne connaît que ce que `calculer_variables` lui donne (`SUJET`,
`DETAILS`, `PREFIX`, `DIR_xxx`) et les contrôles de `verifier`. Les noms
de vos variables sont les vôtres.

### Exemples fournis

| fichier | ce que c'est |
|---|---|
| `exemples/demo.conf` | le bac à sable de `--demo` : chaque mécanisme, commenté |
| `exemples/forensic.conf` | un cas complet : analyse d'une image disque avec la Sleuth Kit, menus, listes emboîtées, fonctions |
| `exemples/pc07.conf` | un poste précis : `source forensic.conf` puis six variables |

---

## Pendant l'exécution

| touche | effet |
|---|---|
| `Entrée` | exécuter |
| `p` | passer cette étape |
| `e` | éditer la ligne, pour cette exécution seulement |
| `r` | ressaisir les `[[valeurs]]` de cette étape |
| `q` | arrêter le script |
| `u` | *(étape répétée)* une itération à la fois |
| `l` | *(étape répétée)* lister les itérations avec leur commande |

| quand | Ctrl-C fait |
|---|---|
| pendant une **commande** | interrompt la commande, pas le script ; il demande si l'on continue |
| pendant une **question** | arrête le script proprement, avec le récapitulatif |
| Ctrl-D à une question | arrêt : plus personne au clavier |

Ctrl-C interrompt la commande en cours, pas la ligne entière : sur `a ; b`,
`b` s'exécutera quand même. Dans vos propres boucles, mettez
`(( INTERROMPU )) && return 130` en première ligne.

### Lire l'écran

Le plan s'affiche au départ, le récapitulatif à la sortie, avec les mêmes
marques ; les itérations d'une étape répétée apparaissent dessous, comme
des sous-tâches.

```
  ○ à faire  ◐ en cours  ● réussie  ✗ échec  ⊘ passée  ⊗ interrompue  ◌ simulée
```

```
  ●  2  Contenu du dossier                                0s
  ●  3  Taille de chaque sous-dossier                 3/3  1s
      ├─ ● sousdossier=documents                          0s
      ├─ ● sousdossier=images                             1s
      └─ ✗ sousdossier=projets                        code 1
```

Au-delà de dix itérations, seules celles qui ont mal tourné sont
détaillées.

---

## Reprendre, filtrer, automatiser

```bash
./tasker.sh -r              # sauter les étapes déjà réussies
./tasker.sh -o 2,5-7        # ne jouer que celles-là
./tasker.sh -f 4            # partir de l'étape 4
./tasker.sh -n              # simulation
./tasker.sh -a              # confirmer chaque étape, même les false
./tasker.sh -y              # ne rien demander
./tasker.sh -y &            # en arrière-plan : le terminal n'est pas touché
```

Les options courtes se combinent (`-yn`) et acceptent une valeur collée
(`-o3`, `-cFICHIER`). Code de sortie : `0` si tout est passé, `1` s'il
reste un échec.

`-r` s'appuie sur l'empreinte du titre et de la commande : modifiez la
commande, l'étape sera rejouée.

### sudo et programmes plein écran

* Le mot de passe de `sudo` est demandé au moment où la commande part,
  y compris avec `log` et depuis une commande de `LISTES`. Avec `-y`,
  personne ne répondrait : le script prévient au démarrage, faites
  `sudo -v` avant.
* Le terminal est rendu tel qu'il était après chaque commande : un
  programme plein écran interrompu ne laisse plus l'écran en mode brut.
* Sous `sudo`, le rapport note qui a lancé (`SUDO_USER`) et l'exécution
  en root.
* Fermer le terminal ou tuer le script laisse quand même un récapitulatif
  et un journal qui dit pourquoi.

---

## Ce qui est écrit

```
<DIR_LOGS>/
├── <PREFIX>_script.log     chaque commande, son code, sa durée
├── <PREFIX>_rapport.txt    le récapitulatif, sujet et opérateur inclus
└── <PREFIX>_etat.txt       les étapes réussies (pour -r)
```

---

## Limites

* Les commandes passent par `eval` : n'y mettez que des commandes que
  vous écrivez vous-même.
* `tail` après un `tee`, oui ; `head`, non : `head` ferme le tube et
  l'étape est comptée en échec (code 141).
* Pas de commande interactive avec l'option `log` : elle perdrait son
  terminal.
* Une sortie sans saut de ligne final colle la ligne de résultat.
* Une commande de `LISTES` ne lit pas le clavier (elle reçoit `/dev/null`).
