# tasker.sh — comprendre en dix minutes

Ce document part de zéro et va jusqu'aux boucles emboîtées. Chaque exemple
est **exécutable tel quel**.

---

## 0. Voir avant de lire

```bash
./tasker.sh --demo
```

Rien à installer : le script fabrique un bac à sable dans `/tmp` et y
rejoue tous ses mécanismes avec `ls`, `wc` et `sha256sum`. C'est le même
moteur, ligne pour ligne, que celui qui exécutera vos commandes. Le tableau
de cette démonstration est dans `exemples/demo.conf`, commenté étape par
étape.

---

## 1. Le modèle mental

Le script n'est qu'un **tableau de lignes**, parcouru de haut en bas. Une
ligne = une étape = une commande shell.

```bash
"Titre|validation|commande"
```

À chaque étape, le script affiche la commande, attend votre accord si
`validation` vaut `true`, l'exécute, note le résultat, passe à la suivante.
Tout le reste — menus, répétitions, journal — sert à remplir la troisième
colonne sans se tromper.

---

## 2. Une étape simple

```bash
COMMANDES=(
"Contenu de /etc|true|ls -l /etc"
)
```

```
──────────────────────────────────────────────────────────
  ◐ 1/1  ━━━━━━━━━━━━  Contenu de /etc
──────────────────────────────────────────────────────────
  $ ls -l /etc
  Entrée exécuter · p passer · e éditer · r ressaisir · q quitter
  ›
```

**Tout ce qui marche dans un terminal marche ici** : redirections, tubes,
tests, `&&`, `||`, et les fonctions que vous écrivez en section 5.

```bash
"Sauvegarde|true|tar czf '$SORTIE/etc.tgz' /etc"
"Aperçu|true|ls -la '$DOSSIER' | tee '$DIR_LOGS/ls.txt' | tail -n 20"
"Si présent|true|[ -s '$SORTIE/etc.tgz' ] && echo ok || echo vide"
```

---

## 3. `$VARIABLE` — ce qu'on connaît à l'avance

Réglé une fois en section 1, ou dans un fichier `-c`, ou avec
`--set NOM=valeur`. Remplacé au lancement.

### ⚠️ Le seul vrai piège

Le tableau est écrit entre **guillemets doubles** : un `$` y est remplacé
*tout de suite*. Une variable qui naîtra **pendant** la commande n'existe
pas encore, et `set -u` arrête le script :

```bash
FAUX   "Boucle|true|for u in a b; do echo home_$u; done"
JUSTE  "Boucle|true|for u in a b; do echo home_\$u; done"
```

Même chose pour `\$(date)`, `\$1`, `\$?`. **Si la variable existe déjà
quand vous éditez le script, pas d'antislash. Sinon, antislash.**

---

## 4. `[[nom]]` — une valeur qu'on ne connaît pas d'avance

```bash
"Fichiers récents|true|find '$DOSSIER' -mtime -[[jours]] -type f"
"Fichiers récents, en détail|true|find '$DOSSIER' -mtime -[[jours]] -type f -ls"
```

`[[jours]]` est demandé quand on **arrive** sur la première étape qui
l'utilise, puis **réutilisé** dans toutes les suivantes.

```
    ┌─ [[jours]]  — utilisé aux étapes 1, 2
    │  la valeur sera réutilisée partout où [[jours]] apparaît
    │   p  passer cette étape   q  quitter
    └─ valeur ›
```

Pour la fournir d'avance : `./tasker.sh -D jours=7`. Pour voir ce qui sera
demandé : `./tasker.sh --vars`.

---

## 5. `LISTES` — transformer la question en menu

Déclarez d'où la valeur peut venir : une commande qui écrit **une valeur
par ligne**, éventuellement suivie d'une tabulation et d'un libellé.

```bash
LISTES=(
"jours|printf '%s\t%s\n' 1 'hier' 7 'cette semaine' 30 'ce mois'"
)
```

```
    ┌─ [[jours]]  — utilisé aux étapes 1, 2
    │
    │   1  1              hier
    │   2  7              cette semaine
    │   3  30             ce mois
    │
    │   a  saisir une autre valeur
    │   p  passer cette étape
    │   q  quitter le script
    └─ votre choix [1] ›
```

Seule la **valeur** (avant la tabulation) entre dans la commande ; le
**libellé** s'affiche. Il reste accessible sous `{{nom_libelle}}`.

---

## 6. `{{nom}}` — répéter une étape

Même tableau `LISTES`, autre syntaxe dans la commande :

```bash
LISTES=(
"sousdossier|lister_dossiers '$DOSSIER'"
)
COMMANDES=(
"Taille de chaque sous-dossier|true|du -sh '{{sousdossier}}'"
)
```

L'étape est **rejouée une fois par valeur** :

```
  ↻  étape répétée — 3 itérations
      1  sousdossier=documents
      2  sousdossier=images
      3  sousdossier=projets
  Entrée tout exécuter · u une par une · l lister · p passer · …
```

* `l` montre les trois commandes en entier avant de vous engager ;
* `u` les déroule une par une, avec une validation chacune ;
* le nombre d'itérations est toujours annoncé **avant** de lancer quoi que
  ce soit, et plafonné par `MAX_ITERATIONS`.

> **Toujours entre apostrophes** : `'{{sousdossier}}'`. Les valeurs
> viennent d'un programme et contiennent des espaces. Le script neutralise
> les apostrophes qu'elles pourraient contenir — `o'brien` passe — à
> condition que le placeholder soit quoté.

---

## 7. Une liste écrite à la main, avec une boucle `for`

Une liste n'est rien de plus qu'une fonction qui écrit une ligne par
valeur. La plus simple possible, fournie en section 5 :

```bash
lister_dossiers() {
    local d
    for d in "$1"/*/; do                  # le / final ne garde que les dossiers
        (( INTERROMPU )) && return 130    # Ctrl-C doit pouvoir sortir de la boucle
        [[ -d "$d" ]] || continue         # aucun dossier : le motif reste tel quel
        d="${d%/}"                        # retire le / final
        printf '%s\t%s\n' "$d" "${d##*/}"  # chemin, tabulation, nom seul
    done
    return 0
}
```

* `for d in "$1"/*/` — le shell remplace `*/` par chaque sous-dossier ; le
  `/` final exclut les fichiers.
* `(( INTERROMPU )) && return 130` — sans cette ligne, Ctrl-C tue le `du`
  en cours mais la boucle repart sur le dossier suivant.
* `[[ -d "$d" ]] || continue` — s'il n'y a aucun dossier, bash laisse le
  motif tel quel ; on l'écarte.
* `printf '%s\t%s\n' "$d" "${d##*/}"` — la **valeur**, une **tabulation**,
  le **libellé**. `${d##*/}` retire tout jusqu'au dernier `/`.

Appelée sur `/home`, elle écrit :

```
/home/alice	alice
/home/bruno	bruno
```

---

## 8. Deux niveaux : la liste qui en appelle une autre

C'est le point qui surprend le plus, et le plus utile. On veut, pour chaque
utilisateur, le contenu de son `.bashrc` — sachant que tous n'en ont pas.

**1. La liste des homes** (celle du § 7) :

```bash
"profil|lister_dossiers '/home'"
```

**2. Une liste qui cherche DANS un profil** :

```bash
lister_bashrc() {
    [[ -f "$1/.bashrc" ]] && printf '%s\t%s\n' "$1/.bashrc" "${1##*/}/.bashrc"
    return 0
}
```

```bash
"bashrc|lister_bashrc '{{profil}}'"
```

Le `{{profil}}` est la clé : cette liste n'a de sens que pour un profil
donné, donc le script la régénère pour chacun.

**3. L'étape**, qui ne mentionne que `{{bashrc}}` :

```bash
"Contenu de chaque .bashrc|true,log|cat '{{bashrc}}'"
```

**Ce que fait le script :**

```
  ↻  étape répétée — 2 itérations
      1  profil=alice · bashrc=alice/.bashrc
      2  profil=carole · bashrc=carole/.bashrc
```

Il a bouclé sur les profils *tout seul*, parce que `bashrc` en dépend.
Bruno n'a pas de `.bashrc` : sa branche ne produit rien et disparaît, sans
erreur. Les étiquettes montrent les deux niveaux.

> **Une liste vide n'est pas une erreur.** C'est une branche qui ne produit
> rien. Le script ne s'arrête que si l'étape entière finit sans aucune
> itération.

Deux `{{listes}}` écrites côte à côte dans une commande s'emboîtent aussi,
de gauche à droite. Essayez : `./tasker.sh --demo -o 5,7`.

---

## 9. Écrire une fonction plutôt qu'une ligne à rallonge

Au-delà de deux ou trois instructions, la ligne devient illisible et les
échappements ingérables. Écrivez une fonction en **section 5** et
appelez-la depuis le tableau. Une fonction d'**étape** termine par un
`return` explicite : ce code devient le ● ou le ✗ du récapitulatif. Une
fonction de **liste** écrit ses valeurs sur la sortie standard et ses
messages d'erreur sur `>&2`.

Pour reprendre une fonction venue d'ailleurs : `exit` → `return`, variables
internes en `local`, et `(( INTERROMPU )) && return 130` dans toute boucle
longue.

---

## 10. Un jeu d'étapes par usage : le fichier `-c`

Un fichier `-c` est du shell. Il peut fixer les variables, mais aussi
redéfinir `calculer_variables`, `verifier`, `definir_commandes` et
ajouter des fonctions. C'est un jeu d'étapes complet, sans copier le
script.

```bash
./tasker.sh -t > mon-cas.conf              # gabarit à compléter
./tasker.sh -c mon-cas.conf
```

`exemples/forensic.conf` en est un exemple complet : l'analyse d'une image
disque avec la Sleuth Kit, avec des menus construits depuis `mmls`, une
liste des profils qui donne l'inode à `fls` et le chemin à l'écran, et le
`.bashrc` de chaque utilisateur exactement comme au § 8. Pour un poste
donné, `exemples/pc07.conf` fait `source forensic.conf` puis règle six
variables.

---

## 11. Touches, Ctrl-C, reprise

**À une étape** : `Entrée` exécuter · `p` passer · `e` éditer pour cette
fois · `r` ressaisir les valeurs · `q` quitter · `u` une itération à la
fois · `l` lister les itérations.

**À une question** : `1 2 3` choisir · `Entrée` la proposition 1 · `a`
autre valeur · `p` passer · `q` quitter. Après `a`, `p` et `q` redeviennent
des valeurs ordinaires.

**Ctrl-C** pendant une commande l'interrompt, pas le script ; à une
question, arrête le script proprement. Sur une étape `a ; b`, `b`
s'exécutera quand même : écrivez `a && b` si ce n'est pas voulu.

```bash
./tasker.sh -r            # sauter les étapes déjà réussies
./tasker.sh -o 2,5-7      # ne jouer que celles-là
./tasker.sh -f 4          # partir de l'étape 4
./tasker.sh -n            # simulation
./tasker.sh -y &          # en arrière-plan, sans question
```

---

## 12. Quand ça ne marche pas

| symptôme | cause la plus fréquente |
|---|---|
| `u: unbound variable` au lancement | un `$` non échappé dans le tableau (§ 3) |
| `les listes n'ont rien donné` | la commande de liste ne renvoie rien : testez-la seule |
| l'étape répétée n'a qu'une itération | la liste ne renvoie qu'une ligne, ou `--list` la fige |
| code 141 | un `head` derrière un `tee` |
| une valeur avec un espace casse la commande | un `{{nom}}` non entouré d'apostrophes |
| `ERREUR de format` | un `\|` dans le titre ou dans le champ validation |
| `calculer_variables doit définir DIR_LOGS` | votre fichier `-c` redéfinit `calculer_variables` sans ce nom |

Le journal `<DIR_LOGS>/<PREFIX>_script.log` contient chaque commande telle
qu'elle a été lancée, son code de retour et sa durée. C'est là qu'il faut
regarder en premier.
