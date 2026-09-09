---
name: conformite-linux
description: Confronte une collecte tasker.sh collecte-linux.conf aux règles internes fournies (charte informatique, politique de sécurité) et rédige un rapport de conformité nominatif, daté et sourcé — comptes et mots de passe, élévation de privilèges, secrets laissés en clair, durcissement du poste, usages (supports amovibles, services personnels en ligne, logiciels installés hors gestionnaire). À utiliser quand on demande si les règles ont été respectées sur un poste, ou quelles mauvaises pratiques s'y observent. Ne juge rien sans une règle écrite, et montre la traduction de chaque règle en contrôle vérifiable.
user-invocable: true
---

# Conformité d'un poste Linux aux règles internes

Vous confrontez une collecte à des **règles fournies**. Votre livrable est un
rapport en français, adossé à un fichier de constats bruts.

## Les deux règles qui priment sur tout

**1 · Un constat n'est pas un manquement.** « PermitRootLogin yes » est un fait.
Qu'il soit interdit dépend de la charte. **Sans règle écrite, pas de
manquement** — au mieux une observation, rangée comme telle. Vous n'êtes pas
l'auteur de la politique de l'entreprise.

**2 · Aucune affirmation sans sa source.** Chaque constat porte son fichier et
le geste qui l'a obtenu. Un lecteur doit pouvoir refaire la vérification.

## Ce que vous nommez

Le rapport est **nominatif au niveau des comptes**. Écrivez-le une fois, en
tête, et tenez-vous-y :

> Ce rapport désigne des **comptes** — des identités numériques. Il n'établit
> pas qui tenait le clavier : une collecte ne le dit jamais. Un manquement
> imputé à un compte n'est pas, par lui-même, imputé à une personne.

Certains constats ne visent personne : `PermitRootLogin yes` est un réglage du
**poste**, pas d'un compte. Le champ `portee` le dit (`poste` ou `compte`) —
respectez-le. Attribuer à un agent une configuration qu'un administrateur a
posée est la faute la plus facile à commettre ici.

## Marche à suivre

### 1 · Relever les constats

```bash
python3 scripts/controles.py <dossier PREFIX/> -o constats.jsonl
```

`python3` et sa bibliothèque standard suffisent. Un constat :

```json
{"id":"C0014","theme":"secrets","constat":"clé privée SSH SANS phrase de passe",
 "valeur":".ssh/id_ed25519","portee":"compte","acteur":"jdupont",
 "source":"COMPTES/PREFIX_jdupont_artefacts.tar.gz → .ssh/id_ed25519",
 "methode":"lecture de l'en-tête de la clé : chiffrement « none »",
 "question":"la charte impose-t-elle une phrase de passe sur les clés privées ?"}
```

Le champ **`question`** est la charnière : il dit ce qu'une règle doit
prévoir pour que ce constat devienne un manquement.

Lancez aussi le skill **`forensic-linux`** : son `faits.jsonl` porte les
**dates** — quand la clé USB a été branchée, quand le service a été visité.
Un manquement daté vaut mieux qu'un manquement constaté.

**Quand les règles sont déjà écrites dans un fichier `.regles`**, ajoutez-le :

```bash
python3 scripts/controles.py <dossier PREFIX/> \
        --regles references/regles/usage-non-professionnel.regles \
        --faits faits.jsonl -o constats.jsonl
```

Les constats portent alors le numéro de la règle cherchée. Voir le §3.

### 2 · Lire les règles

Elles arrivent en texte ou en Markdown. Si vous recevez un PDF ou un document
Word, demandez une version texte — n'inventez pas le contenu d'un fichier que
vous ne pouvez pas lire.

Numérotez chaque règle telle qu'elle est écrite. Si la charte a déjà des
articles, reprenez sa numérotation ; sinon, posez la vôtre et dites-le.

### 3 · Traduire les règles en contrôles — et le montrer

C'est l'étape la plus délicate, et **elle doit être visible dans le rapport**.

Une règle comme « l'agent veille à la confidentialité des données » n'est pas
vérifiable telle quelle. La rendre vérifiable est une **interprétation**, et un
lecteur doit pouvoir la contester. Produisez donc, avant tout constat, un
tableau :

| règle | ce qu'elle dit | contrôle retenu | constats concernés |
|---|---|---|---|
| Art. 4.2 | « les mots de passe sont personnels et renouvelés » | comptes sans mot de passe, sans expiration, ou hachés en MD5 | C0006, C0008, C0009 |
| Art. 6 | « l'agent veille à la confidentialité » | *trop général pour un contrôle direct — voir les règles non vérifiables* | — |

### Les règles écrites d'avance : le fichier `.regles`

Une règle que l'on rencontre à chaque dossier n'a pas à être retraduite chaque
fois. `references/regles/` contient des fichiers où la traduction est écrite,
**à la main et en clair** : une règle par bloc, sa phrase recopiée de la charte,
puis les indices à chercher — un domaine dans un navigateur, un programme dans
la liste des paquets, un fichier dans le dossier personnel, un réseau sans fil,
des heures ouvrées.

    regle: R2
    titre: Logiciels de jeu vidéo
    texte: L'installation de logiciels de jeu sur le poste est interdite.
    programme: (?i)\b(steam|lutris|minecraft)\b        # ludothèques
    fichier: (?i)/(Games?|Jeux)/

**Ces fichiers ne sont pas la charte de l'entreprise.** Avant de vous en servir,
confrontez chaque bloc à la charte fournie : retirez ce qu'elle ne dit pas,
ajoutez ce qu'elle dit. Un bloc dont le `texte:` ne se retrouve pas dans la
charte doit être retiré, ou signalé comme une observation sans règle.

Le fichier vous appartient : ajouter une règle, c'est ajouter un bloc — jamais
toucher au code. Le format est décrit en tête de
`references/regles/usage-non-professionnel.regles`.

Trois choses à savoir pour le rapport :

- **Le motif est dans le constat.** Le champ `methode` cite l'expression
  cherchée : le lecteur peut la refaire, et la contester. Le champ `question`
  ne demande plus « quelle règle ? » mais « cette traduction est-elle fidèle ? ».
- **Ce qu'un indice prouve est écrit dans le constat**, dans `note`. Un domaine
  prouve une consultation ; un paquet, une installation ; un fichier, une
  présence ; un réseau sans fil, une association ; une heure, une ouverture de
  session. **Recopiez cette limite dans le rapport** au lieu de la résumer.
- **Une règle non cherchée n'est pas une règle respectée.** Quand la pièce
  manque, le constat est de thème `limite` (« règle R6 : aucun profil de
  connexion réseau ») ; quand la pièce est là et que rien n'a été trouvé, il est
  de thème `conforme` — et dit lui-même que cela ne prouve pas le respect de la
  règle. Ces deux cas vont respectivement au §7 et au §6 du rapport, jamais au §3.

Reportez le tableau du §3 depuis le fichier : `regle`, `texte`, les indices, et
les constats obtenus. Le manifeste `constats-manifeste.json` contient le
fichier de règles employé, son empreinte et la liste des motifs — de quoi
refaire le tableau sans rien deviner.

Trois interdits sur cette table :

- **N'élargissez pas une règle.** « Les supports amovibles doivent être
  chiffrés » ne dit pas « les supports amovibles sont interdits ».
- **N'inventez pas de règle** parce qu'un constat vous paraît grave. Une clé
  privée sans phrase de passe est une mauvaise pratique reconnue — si la charte
  n'en dit rien, elle va dans « observations sans règle correspondante », pas
  dans les manquements.
- **Dites quand une règle n'est pas vérifiable** avec cette collecte. C'est une
  information utile pour qui écrira la prochaine charte.

### 4 · Rédiger

Écrivez `rapport-conformite-<PREFIX>.md` :

1. **Objet et périmètre** — la machine, la collecte, les règles employées avec
   leur date de version, et la phrase sur les comptes (ci-dessus).
2. **Comment les règles ont été traduites** — le tableau du §3. Avant les
   résultats : le lecteur doit pouvoir contester la méthode avant les
   conclusions.
3. **Manquements établis** — un tableau : règle, constat, compte ou poste,
   date si elle est connue, identifiants `C0014` et `F0123`. Rien ici sans
   règle en face.
4. **Observations sans règle correspondante** — les mauvaises pratiques que la
   charte ne couvre pas. Ni accusation ni silence : une matière pour la
   prochaine version de la charte.
5. **Règles non vérifiables avec cette collecte** — et ce qu'il faudrait
   collecter pour les vérifier.
6. **Ce qui est conforme** — ne l'omettez pas. Une clé protégée par une phrase
   de passe, un pare-feu actif : un rapport qui ne relève que le négatif se
   discrédite, et l'agent concerné le sait.
7. **Limites** — pièces manquantes de la collecte (les constats de catégorie
   `limite` du skill forensic), historiques non datés, absences dont on ne sait
   pas si elles viennent du système ou de la collecte.
8. **Annexe : méthode** — les commandes, les empreintes des manifestes, la
   table `id → source`.

## Ce qu'il ne faut pas faire

- **Ne qualifiez pas l'intention.** Vous constatez qu'un service de stockage
  personnel a été visité. Vous ne savez pas si des fichiers de l'entreprise y
  sont partis — sauf si un fait le montre, et alors citez-le.
- **N'aggravez pas par accumulation.** Dix constats mineurs ne font pas un
  manquement grave. Chaque ligne se juge sur sa règle.
- **Ne datez pas ce qui n'est pas daté.** Un `.bash_history` sans
  `HISTTIMEFORMAT` ne porte aucune date : la position d'une ligne ne prouve pas
  son moment. Le skill forensic le signale, respectez-le.
- **N'attribuez pas un réglage du poste à un compte.** Voir `portee`.
- **Ne présumez pas de la responsabilité hiérarchique.** Un `sudo NOPASSWD`
  peut avoir été posé par le service informatique. Dites ce que vous voyez, et
  que l'origine du réglage n'est pas établie par la collecte.
- **Ne concluez pas à la place de qui décide.** Vous rapportez des écarts. La
  suite — rappel, entretien, sanction — n'est pas votre objet, et le rapport ne
  doit rien en suggérer.

## Si les règles ne sont pas fournies

Ne devinez pas. Rendez alors un **état des lieux** : les constats rangés par
thème, avec pour chacun la question qu'une règle devrait trancher — c'est
exactement le champ `question`. Dites en tête que ce document n'est pas un
rapport de conformité, faute de règles, et qu'aucun manquement n'y est établi.

`references/regles-type.md` liste les règles qu'on rencontre le plus souvent
dans une charte informatique et le contrôle qui leur correspond ici. **Ce n'est
pas la charte de l'entreprise** : c'est une aide pour comparer, et pour repérer
ce qu'une charte omet.
