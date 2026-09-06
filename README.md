# tasker.sh

Enchaîne des commandes, **validées une à une**. Un tableau de lignes, un
journal, et de quoi répéter une étape sur une liste de valeurs.

```bash
./tasker.sh --demo      # essayer, sans rien installer
./tasker.sh -h          # l'aide
./tasker.sh -l          # voir le plan sans rien lancer
./tasker.sh             # lancer
```

Prérequis : bash 4.3. Pour comprendre en profondeur : **[TUTORIEL.md](TUTORIEL.md)**.

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
"Contenu|true|ls -la '$DOSSIER'"          # section 2
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

## Les listes (section 3)

Une liste = un nom, et une commande qui écrit **une valeur par ligne**.

```bash
LISTES=(
"sousdossier|lister_dossiers '$DOSSIER'"
"jours|printf '%s\n' 1 7 30"
)
```

### Avec un libellé : `valeur<TAB>libellé`

La valeur va dans la commande, le libellé s'affiche.

```bash
"jours|printf '%s\t%s\n' 1 'hier' 7 'cette semaine' 30 'ce mois'"
```

```
    │   1  1              hier
    │   2  7              cette semaine
    │   3  30             ce mois
```

Le libellé reste disponible : `{{jours_libelle}}`.

### Le même nom en `[[ ]]` ou en `{{ }}`

| dans la commande | ce qui se passe |
|---|---|
| `[[jours]]` | menu numéroté, **une** valeur choisie |
| `{{jours}}` | l'étape est rejouée pour **chaque** valeur |

### Une liste qui en utilise une autre

```bash
"profil|lister_dossiers '/home'"
"bashrc|lister_bashrc '{{profil}}'"       # dépend de profil
```

```bash
"Chaque .bashrc|true|cat '{{bashrc}}'"     # boucle sur les profils toute seule
```

```
      1  profil=alice · bashrc=alice/.bashrc
      2  profil=carole · bashrc=carole/.bashrc
```

Une liste vide n'est pas une erreur : la branche ne produit rien.

### Écrire une fonction de liste

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

## Fichier de configuration `-c`

Du shell. Il fixe les variables, et peut redéfinir les commandes.

```bash
# poste.conf
DOSSIER="/srv/data"
OPERATEUR="M. Dupont"
```

```bash
./tasker.sh -c poste.conf
./tasker.sh -c poste.conf -s DOSSIER=/autre     # surcharge ponctuelle
./tasker.sh -t > poste.conf                     # gabarit à compléter
```

Un jeu d'étapes complet, sans copier le script :

```bash
# cas.conf
DOSSIER="/srv/data"
definir_commandes() {
    COMMANDES=("Contenu|true|ls '$DOSSIER'")
    LISTES=()
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
| `exemples/demo.conf` | le bac à sable de `--demo` |
| `exemples/forensic.conf` | analyse d'une image disque : menus, listes emboîtées, fonctions |
| `exemples/pc07.conf` | `source forensic.conf` + six variables |

---

## Ce que le script attend de vous

Les noms de vos variables sont libres, **sauf ceux-ci**. Le script les lit ;
ne les supprimez pas, renommez-les encore moins.

### Dans la section 1

| variable | rôle | valeurs |
|---|---|---|
| `OPERATEUR` | qui a lancé, noté au bandeau, au journal et au rapport | texte ; `${SUDO_USER:-$USER}` prend la vraie personne sous sudo |
| `TOUT_VALIDER` | confirmer chaque étape, même les `false` | `true` / `false` (ou `-a`) |
| `MAX_ITERATIONS` | plafond d'une étape répétée, au-delà elle est tronquée | entier ≥ 1 |
| `REQUIS` | binaires vérifiés au départ ; absents = avertissement | tableau : `(du df)` |
| `INTRO` | texte affiché après le bandeau (facultatif) | texte, plusieurs lignes possibles |

### Dans `calculer_variables` (section 4)

Recalculée après `-c` et `--set`, pour que tout suive la dernière valeur.

| variable | rôle | exemple |
|---|---|---|
| `SUJET` | titre court, en tête et au récapitulatif | `"$PC · $SALLE"` |
| `DETAILS` | lignes du bandeau de départ | `("image=$IMAGE" "fuseau=$TZ")` — clé sans accent |
| `PREFIX` | préfixe des fichiers écrits, sans `/` | `"${PC}_${SALLE}"` |
| `DIR_LOGS` | dossier du journal, du rapport et de l'état de reprise | `"$DEST/logs"` |
| `DIR_xxx` | tout autre dossier de travail : vérifié, créé au besoin | `DIR_BODY`, `DIR_SORTIE`… |

`SUJET`, `PREFIX` et `DIR_LOGS` sont obligatoires : le script refuse de
partir sans.

### Les trois fonctions appelées par le script

| fonction | quand | ce qu'elle doit faire |
|---|---|---|
| `calculer_variables` | après `-c` et `--set` | poser les variables ci-dessus |
| `verifier` | avant la première étape | vos contrôles ; `return 1` arrête tout |
| `definir_commandes` | après `calculer_variables` | remplir `COMMANDES` et `LISTES` |

Un fichier `-c` peut remplacer n'importe laquelle des trois. S'il écrit
`COMMANDES=(…)` directement, `definir_commandes` n'est pas appelée.

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
| `-s`, `--set` | `NOM=valeur` | fixer une variable de la section 1 |
| `-D`, `--var` | `nom=valeur` | répondre d'avance à `[[nom]]` |
| `--list` | `nom=a,b,c` | figer `{{nom}}` sur ces valeurs |
| `--vars` | | montrer les `[[ ]]` et `{{ }}` attendus |
| `-t`, `--template` | | écrire un fichier `-c` sur la sortie standard |
| `-l`, `--plan` | | le plan, sans rien lancer |
| `-n`, `--dry-run` | | tout afficher, rien exécuter |
| `-o`, `--only` | `2,5-7` | ne jouer que ces étapes |
| `-f`, `--from` | `4` | partir de l'étape 4 |
| `-r`, `--resume` | | sauter les étapes déjà réussies |
| `-a`, `--ask` | | confirmer chaque étape, même les `false` |
| `-y`, `--yes` | | ne rien demander |
| `--color` | `auto` `always` `never` | couleur ; `--no-color` = `never` |
| `--demo` | | bac à sable |

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

| Ctrl-C | |
|---|---|
| pendant une commande | l'interrompt ; le script demande si l'on continue |
| pendant une question | arrête le script, avec le récapitulatif |

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

---

## Ce qui est écrit

```
<DIR_LOGS>/<PREFIX>_script.log     chaque commande, code, durée
<DIR_LOGS>/<PREFIX>_rapport.txt    le récapitulatif
<DIR_LOGS>/<PREFIX>_etat.txt       les étapes réussies (pour -r)
```

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

* Les commandes passent par `eval` : n'y mettez que les vôtres.
* `head` derrière un `tee` ferme le tube : code 141. Utilisez `tail`.
* Pas de commande interactive avec `log`.
* Une commande de `LISTES` ne lit pas le clavier.
* Ctrl-C interrompt la commande en cours, pas la ligne : sur `a ; b`, `b` tourne. Écrivez `a && b`.
