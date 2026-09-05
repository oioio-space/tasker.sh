# forensic.sh — comprendre en dix minutes

Ce document part de zéro et va jusqu'aux boucles imbriquées. Chaque
exemple est **exécutable tel quel**.

---

## 0. Voir avant de lire

```bash
./forensic.sh --demo
```

Aucune image disque, aucun outil forensique, rien à installer : le script
fabrique un bac à sable dans `/tmp/forensic-demo` et y rejoue tous ses
mécanismes avec `ls`, `wc` et `sha256sum`. C'est le même moteur, ligne
pour ligne, que celui qui tournera sur vos scellés.

Le tableau de cette démonstration est dans `exemples/demo.conf`, commenté
étape par étape. Lisez-le en parallèle de ce tutoriel.

---

## 1. Le modèle mental

Le script n'est rien d'autre qu'un **tableau de lignes**, parcouru de
haut en bas. Une ligne = une étape = une commande shell.

```bash
"Titre|validation|commande"
```

À chaque étape, le script :

1. affiche la commande **avant** de la lancer ;
2. attend votre accord si `validation` vaut `true` ;
3. l'exécute, note le résultat, passe à la suivante.

C'est tout. Le reste — menus, répétitions, journal — sert à remplir la
troisième colonne sans se tromper.

---

## 2. Une étape toute simple

```bash
COMMANDES=(
"Contenu de /etc|true|ls -l /etc"
)
```

```
──────────────────────────────────────────────────────────
  1/1  ━━━━━━━━━━━━  Contenu de /etc
──────────────────────────────────────────────────────────
  $ ls -l /etc
  Entrée exécuter · p passer · e éditer · r ressaisir · q quitter
  ›
```

`validation` à `false` aurait lancé la commande sans rien demander.

**Tout ce qui marche dans un terminal marche ici** : redirections, tubes,
tests, `&&`, `||`.

```bash
"Timeline|true|mactime -b '$DIR_BODY/x.body' -z 'Europe/Paris' -d -y > '$DIR_TIMELINE/x.csv'"
"Aperçu|true|mmls '$IMAGE' | tee '$DIR_LOGS/mmls.txt' | tail -n 20"
"Si présent|true|[ -s '$DIR_BODY/x.body' ] && echo ok || echo vide"
```

---

## 3. `$VARIABLE` — ce qu'on connaît à l'avance

`$IMAGE`, `$DIR_BODY`, `$PREFIX`… sont remplacés au lancement. Vous les
réglez une fois en section 1, ou dans un fichier `-c`.

### ⚠️ Le seul vrai piège du script

Le tableau est écrit entre **guillemets doubles**. Un `$` y est donc
remplacé *tout de suite*, à la lecture du tableau. C'est ce qu'on veut
pour `$IMAGE`, qui existe déjà. Mais une variable qui naîtra **pendant**
la commande n'existe pas encore, et `set -u` arrête le script :

```bash
FAUX   "Boucle|true|for u in a b; do echo home_$u; done"
       → u: unbound variable, avant même que rien ne démarre

JUSTE  "Boucle|true|for u in a b; do echo home_\$u; done"
       → le \$ protège u jusqu'à l'exécution
```

Même chose pour `\$(date)`, `\$1`, `\$?`, `\$!`.

**Règle simple : si la variable existe déjà quand vous éditez le script,
pas d'antislash. Sinon, antislash.**

---

## 4. `[[nom]]` — une valeur qu'on ne connaît pas d'avance

```bash
"Fichiers|true|fls -r -p -m / -o [[offset]] '$IMAGE' > '$DIR_BODY/x.body'"
"Inodes|true|ils -m -o [[offset]] '$IMAGE' > '$DIR_BODY/y.body'"
```

`[[offset]]` est demandé quand on **arrive** sur la première étape qui
l'utilise, puis **réutilisé** dans toutes les suivantes. Vous ne le
tapez qu'une fois.

```
    ┌─ [[offset]]  — sert aux étapes 2, 3
    │  la valeur sera réutilisée dans toutes les étapes qui la demandent
    │   p  passer cette étape   q  quitter
    └─ valeur ›
```

Pour la fournir d'avance, sans être interrompu :

```bash
./forensic.sh --vars                # quels noms sont attendus ?
./forensic.sh --var offset=2048     # répétable
```

---

## 5. `LISTES` — transformer la question en menu

Recopier un offset à la main est la première source d'erreur de toute la
chaîne. Déclarez d'où la valeur peut venir :

```bash
LISTES=(
"offset|lister_partitions '$IMAGE'"
)
```

`lister_partitions` écrit **une valeur par ligne**. La question devient :

```
    ┌─ [[offset]]  — sert aux étapes 2, 3
    │
    │   1  2048        NTFS / exFAT (0x07) — 40.0 Go
    │   2  83884032    Linux (0x83) — 10.0 Go
    │
    │   a  saisir une autre valeur
    │   p  passer cette étape
    │   q  quitter le script
    └─ votre choix [1] ›
```

### Valeur et libellé

Une ligne de liste peut s'écrire `valeur⇥libellé` (une **tabulation**).
Seule la valeur entre dans la commande ; le libellé sert à l'affichage.

C'est ce qui permet à `lister_homes` de renvoyer

```
51-144-1	Users/alice
52-144-1	Users/bruno
```

et donc de donner **l'inode** à `fls` — qui ne comprend que ça — tout en
vous montrant **le chemin** — le seul que vous sachiez lire.

Le libellé reste accessible sous `{{nom_libelle}}`.

---

## 6. `{{nom}}` — répéter une étape

Même tableau `LISTES`, autre syntaxe dans la commande :

```bash
LISTES=(
"home|lister_homes '$IMAGE' '[[offset]]' '$OS'"
)

COMMANDES=(
"Inventaire par profil|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' '{{home_libelle}}' '$DIR_BODY'"
)
```

L'étape est **rejouée une fois par valeur** :

```
  ↻  étape répétée — 3 itérations
      1  home=Users/alice
      2  home=Users/bruno
      3  home=Users/celia
  Entrée tout exécuter · u une par une · l lister · p passer · … 
```

* `l` montre les trois commandes en entier avant de vous engager ;
* `u` les déroule une par une, avec une validation chacune ;
* le nombre d'itérations est **toujours annoncé avant** de lancer quoi
  que ce soit, et plafonné par `MAX_ITERATIONS` (section 1).

> **Toujours entre apostrophes** : `'{{home}}'`. Les valeurs viennent
> d'un programme et contiennent des espaces. Le script neutralise les
> apostrophes qu'elles pourraient contenir — `logistique/o'brien` passe
> sans encombre — **à condition** que le placeholder soit quoté.

---

## 7. Deux niveaux : la commande « récursive »

Voilà le point qui surprend le plus, et c'est le plus utile.

```bash
LISTES=(
"home|lister_homes '$IMAGE' '[[offset]]' '$OS'"
"fichier|lister_fichiers '$IMAGE' '[[offset]]' '{{home}}'"
)
```

La liste `fichier` a besoin de `{{home}}`. Donc, quand vous écrivez :

```bash
"Hachage|true|hacher_fichier '$IMAGE' '[[offset]]' '{{fichier}}' '{{fichier_libelle}}' >> '$DIR_LOGS/h.txt'"
```

…le script **remonte la chaîne tout seul** : il boucle d'abord sur les
profils, régénère la liste des fichiers pour chacun, puis exécute la
commande pour chaque fichier de chaque profil.

```
  ↻  étape répétée — 3 itérations
      1  home=Users/alice · fichier=Users/alice/notes.txt
      2  home=Users/alice · fichier=Users/alice/secret.doc (supprimé)
      3  home=Users/bruno · fichier=Users/bruno/cv.pdf
```

Vous n'avez écrit qu'une seule liste dans la commande.

**Les deux façons de faire :**

| ce que vous écrivez | ce qui se passe |
|---|---|
| `'{{fichier}}'` | la boucle sur les homes se déclenche toute seule |
| `'{{home}}' '{{fichier}}'` | pareil, mais vous avez aussi `{{home}}` sous la main dans la commande |

Deux `{{listes}}` écrites côte à côte s'emboîtent **de gauche à droite**.

Essayez-le tout de suite :

```bash
./forensic.sh --demo --seulement 5
```

---

## 8. Écrire une fonction plutôt qu'une ligne à rallonge

Au-delà de deux ou trois instructions, la ligne devient illisible et les
échappements ingérables. Écrivez une fonction en **section 4** :

```bash
lister_agents() {
    local d="$1" a
    for a in "$d"/*/; do
        (( INTERROMPU )) && return 130     # sans ça, Ctrl-C ne sort pas de la boucle
        [[ -d "$a" ]] || continue
        a="${a%/}"
        printf '%s\t%s\n' "$a" "${a##*/}"  # valeur <TAB> libellé
    done
    return 0
}
```

et appelez-la :

```bash
LISTES=( "agent|lister_agents '$DEMO_RACINE/[[service]]'" )
```

Une fonction de **liste** écrit ses valeurs sur la sortie standard, et
ses messages d'erreur sur `>&2` — sinon ils seraient pris pour des
valeurs.

Une fonction d'**étape** termine par un `return` explicite : ce code
devient le ✔ ou le ✖ du récapitulatif.

Pour reprendre une fonction venue d'un autre script : remplacez `exit`
par `return`, déclarez les variables internes en `local`, et méfiez-vous
de `set -u`.

---

## 9. Les options d'une étape

Après `true` ou `false`, séparées par des virgules :

```bash
"Table des partitions|true,log|mmls '$IMAGE'"
"Inodes non alloués|true,continu|ils -m -o [[offset]] '$IMAGE' > '…'"
"Étape critique|true,stop|…"
```

| option | effet |
|---|---|
| `log` | la sortie de la commande est recopiée dans le journal |
| `continu` | un échec est ignoré, sans question — pour `ils`, qui échoue normalement sur NTFS |
| `stop` | un échec arrête tout, sans question |

> `log` fait passer la commande dans un tube : ne le mettez **jamais** sur
> une commande interactive comme `photorec`, qui perdrait son terminal.

---

## 10. Ce que fait chaque touche

**À une étape**

| touche | effet |
|---|---|
| `Entrée` | exécuter |
| `p` | passer cette étape |
| `e` | éditer la ligne, pour cette exécution seulement |
| `r` | ressaisir les `[[valeurs]]` de cette étape (et régénérer ses listes) |
| `q` | arrêter le script |
| `u` | *(étape répétée)* dérouler les itérations une par une |
| `l` | *(étape répétée)* voir toutes les itérations avec leur commande |

**À une question de valeur**

| touche | effet |
|---|---|
| `1` `2` `3` | choisir dans le menu |
| `Entrée` | prendre la proposition 1 |
| `a` | saisir une autre valeur |
| `p` | passer cette étape |
| `q` | quitter le script |

Après un `a`, `p` et `q` redeviennent des valeurs ordinaires — sinon une
partition nommée `p` serait impossible à saisir.

---

## 10 bis. Lire l'écran

Le plan est affiché au démarrage, le récapitulatif à la sortie. Mêmes
marques dans les deux, et les itérations d'une étape répétée
apparaissent en dessous d'elle, comme des sous-tâches.

```
  ○  à faire        ◐  en cours       ●  réussie
  ✗  échec          ⊘  passée         ⊗  interrompue
  ◌  simulée (-n)
```

```
  ●  1  Table des partitions                            0s
  ⊘  3  Inodes non alloués                          passee
  ●  6  Inventaire par utilisateur                 3/3  4s
      ├─ ● home=Users/alice                             1s
      ├─ ● home=Users/bruno                             2s
      └─ ✗ home=Users/celia                        code 1
```

Au-delà de dix itérations, seules celles qui ont mal tourné sont
détaillées, suivies d'un « … et N itérations réussies » : une étape
jouée trois cents fois n'a pas sa place en entier dans un récapitulatif.

---

## 11. Ctrl-C : deux situations, deux réponses

| quand | ce qui se passe |
|---|---|
| pendant une **commande** | la commande est interrompue, **pas** le script ; il vous demande si vous continuez avec la suivante |
| pendant une **question** | le script s'arrête proprement, avec le récapitulatif et le rapport |
| `Ctrl-D` à une question | plus personne au clavier : arrêt, plutôt qu'une réponse inventée |

Deux détails qui se paient cher si on les découvre en séance :

* Ctrl-C interrompt **la commande en cours**, pas la ligne entière. Sur
  une étape `commande_a ; commande_b`, `commande_b` s'exécutera quand
  même. Écrivez `commande_a && commande_b` si ce n'est pas ce que vous
  voulez.
* Dans une boucle d'une de **vos** fonctions, ajoutez
  `(( INTERROMPU )) && return 130` en première ligne, sans quoi Ctrl-C
  tue l'itération en cours mais pas la boucle.

---

## 12. Reprendre après un incident

```bash
./forensic.sh --reprendre         # saute les étapes déjà réussies
./forensic.sh --seulement 2,5-7   # ne joue que celles-là
./forensic.sh --depuis 4          # repart de l'étape 4
./forensic.sh -n                  # simulation : montre tout, n'exécute rien
./forensic.sh --etapes            # le plan, sans rien exécuter
```

`--reprendre` s'appuie sur l'empreinte du **titre et de la commande** :
si vous modifiez la commande, l'étape est rejouée.

Code de sortie : `0` si tout est passé, `1` s'il reste un échec — de quoi
enchaîner `./forensic.sh -c pc07.conf && ./archiver.sh`.

---

## 13. Recettes forensiques

**Un body file par profil, pour ne pas filtrer la timeline complète**

```bash
"Inventaire par profil|true|inventorier_home '$IMAGE' '[[offset]]' '{{home}}' '{{home_libelle}}' '$DIR_BODY'"
```

**Hacher chaque fichier de chaque profil**

```bash
"Hachage|true|hacher_fichier '$IMAGE' '[[offset]]' '{{fichier}}' '{{fichier_libelle}}' >> '$DIR_LOGS/${PREFIX}_hashes.txt'"
```

**Ne lancer une étape que si l'entrée existe**

```bash
"Timeline|true|if [ -s '$DIR_BODY/${PREFIX}_full.body' ]; then mactime -b '$DIR_BODY/${PREFIX}_full.body' -z '$TZ_MACTIME' -d -y > '$DIR_TIMELINE/${PREFIX}_timeline.csv'; else echo 'body vide, rien a faire'; fi"
```

**Garder la sortie et la voir, sans noyer le terminal**

```bash
"Table des partitions|true|mmls '$IMAGE' | tee '$DIR_LOGS/mmls.txt' | tail -n 20"
```

> `tail` après un `tee`, oui ; `head`, non. `head` ferme le tube, la
> commande amont meurt d'un `SIGPIPE` et l'étape est comptée en échec
> (code 141).

**Un fichier de configuration par poste, sans jamais éditer le script**

```bash
# postes/pc07.conf
IMAGE="/images/pc07.dd"
PC="PC07" ; SALLE="B204" ; OS="windows"
OPERATEUR="M. Bachmann"
TZ_MACTIME="Europe/Paris"
```

```bash
./forensic.sh -c postes/pc07.conf
./forensic.sh -c postes/pc07.conf --image /images/autre.dd   # surcharge ponctuelle
```

---

## 14. Quand ça ne marche pas

| symptôme | cause la plus fréquente |
|---|---|
| `u: unbound variable` au lancement | un `$` non échappé dans le tableau (§3) |
| `les listes n'ont rien donné` | la commande de liste ne renvoie rien : testez-la seule dans un terminal |
| l'étape répétée n'a qu'une itération | la liste ne renvoie qu'une ligne, ou `--liste` la fige |
| code 141 | un `head` derrière un `tee` |
| une valeur avec un espace casse la commande | un `{{nom}}` non entouré d'apostrophes |
| `ERREUR de format` | un `\|` dans le titre ou dans le champ validation |

Le journal `logs/<prefixe>_script.log` contient chaque commande telle
qu'elle a été lancée, son code de retour et sa durée. C'est là qu'il faut
regarder en premier.
