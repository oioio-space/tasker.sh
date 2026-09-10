# Chercher ce que l'on sait déjà : le fichier d'indicateurs

L'analyste arrive souvent avec quelque chose en main — l'empreinte d'un fichier
vu sur un autre poste, une adresse, un nom de domaine, un mot. L'extracteur
les cherche dans **toute** la collecte, fichier par fichier, membre d'archive
par membre d'archive, photorec compris :

    python3 scripts/extraire.py <collecte> -o faits.jsonl --indicateurs ce-que-je-cherche.txt

Le fichier s'écrit à la main, une ligne par indicateur, `type: valeur`, et un
`#` pour dire d'où vient l'indicateur — ce commentaire est repris dans le fait :

    # ce que le poste voisin a montré
    sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08   # rapport.docx exfiltré
    md5: 5d41402abc4b2a76b9719d911017c592
    texte: RAPPORT-CONFIDENTIEL-2026
    regex: CONF-\d{4}-[A-Z]{3}
    ip: 203.0.113.42                     # serveur de commande vu dans le pare-feu
    domaine: mise-a-jour-urgente.example
    fichier: *.torrent
    fichier: id_rsa

| type | ce qui est comparé | comment |
|---|---|---|
| `sha256:` `sha1:` `md5:` | le contenu de chaque fichier | empreinte calculée et comparée ; seules les empreintes demandées sont calculées |
| `texte:` | les octets de chaque fichier | recherche sans tenir compte de la casse |
| `regex:` | les octets de chaque fichier | expression Python, appliquée aux octets |
| `ip:` `domaine:` | les octets de chaque fichier | comme un texte — dans les journaux, les bases de navigateur, `hosts`, `known_hosts` |
| `fichier:` | le **nom** de chaque fichier ou membre | motif de nom (`*.torrent`, `id_rsa`, `*/Downloads/*`) |

Chaque trouvaille est un fait de catégorie **`indicateur`**, avec la pièce, le
geste, et pour un texte les soixante octets autour de la première occurrence.
Un indicateur qui n'est **nulle part** donne aussi un fait — « absent de la
collecte » —, avec la réserve qui va avec : absent des pièces collectées, pas
forcément du poste.

## Ce qu'il faut savoir avant de conclure

- **Une empreinte compare des contenus entiers.** Un fichier modifié d'un
  octet ne correspond plus. Pour un document qu'on a pu retoucher, cherchez
  aussi un `texte:` qui lui est propre.
- **Les archives sont lues membre par membre**, jamais l'archive comme un
  bloc : l'empreinte d'un fichier collecté est celle du fichier, pas du tar.
- **Les fichiers de photorec sont sans nom ni date.** Une empreinte qui y
  correspond prouve que le contenu a existé sur le disque — pas où, ni quand.
  La timeline ou `recently-used.xbel` peuvent dire le reste.
- **Une chaîne dans une base de navigateur** peut venir d'une page libérée :
  la visite a existé, mais sa date se lit dans les faits `navigation`, pas ici.
- **Un texte court** (`texte: admin`) touche partout et ne prouve rien. Prenez
  ce qui est propre à ce que vous cherchez.

## Et dans le skill de conformité

Les mêmes recherches se font dans une règle, avec l'indice `chaine:` — pour
une chaîne ou une expression — et les indices `domaine:` ou `fichier:`. Les
empreintes, elles, ne se cherchent qu'ici : le rapport de conformité reprend
les faits `indicateur` de `faits.jsonl` quand on lui donne `--faits`.


## Ce que l'outil cherche de lui-même

Indépendamment de `--indicateurs`, une liste courte est passée sur toute la
collecte à chaque extraction. Les faits sortent dans la catégorie `interet`.

| motif | ce qu'il attrape |
|---|---|
| clé privée | l'en-tête `-----BEGIN … PRIVATE KEY` |
| mot de passe en clair | `password=`, `passwd:`, `mot_de_passe =` suivi d'au moins six caractères |
| identifiants dans une URL | `schéma://utilisateur:secret@hôte` |
| chaîne de connexion | `mysql://`, `postgresql://`, `mongodb://`, `redis://`, `amqp://`, `ldap://` |
| jeton AWS, GitHub, Slack, clé Google | les formes fixes `AKIA…`, `ghp_…`, `xoxb-…`, `AIza…` |
| adresse en .onion | un service accessible seulement par Tor |
| clé de réseau sans fil | `psk=` suivi d'au moins huit caractères |
| couple identifiant/mot de passe | `adresse@domaine:secret`, la forme des listes issues de fuites |

**Pourquoi la liste est si courte.** Sur des dizaines de gigaoctets d'octets
bruts, un motif approximatif ne rend pas un indice : il rend des milliers de
faux, et un rapport que personne ne relit. N'y figure donc que ce qui a une
forme reconnaissable et peu d'homonymes.

Ont été écartés délibérément, et il vaut mieux le savoir que le redécouvrir :

- **adresses bitcoin et ethereum** — du base58 et de l'hexadécimal, qu'un
  disque produit par accident à la pelle ;
- **IBAN génériques** — deux lettres, deux chiffres et de l'alphanumérique :
  la moitié des identifiants de paquets y ressemblent ;
- **numéros de carte bancaire** — ils demandent une vérification de Luhn
  qu'une expression rationnelle ne sait pas faire. Sans elle, ce sont seize
  chiffres, et un disque en est plein.

Si l'un de ces trois vous intéresse pour une affaire précise, donnez-le en
`regex:` dans votre propre fichier d'indicateurs : vous saurez alors que le
bruit est attendu, ce qui n'est pas la même chose que de le subir.

**Où ça cherche, et pourquoi c'est là que ça compte.** Le parcours couvre
toute la collecte, mais deux endroits n'ont aucun autre lecteur dans le
rapport :

- `STRINGS/*.txt` — le texte brut du périphérique, lu en flux ; un secret
  effacé du système de fichiers peut y être encore ;
- `PHOTOREC/` — les fichiers récupérés n'ont ni nom ni date, mais ils ont un
  contenu. C'est souvent là que se trouve le brouillon de configuration ou la
  clé qu'on avait supprimée.

Le fait porte le **décalage en octets** de la première occurrence — compté par
l'extracteur au fil de sa lecture, et non repris de `strings`, qui est appelé
nu — et le texte qui l'entoure : de quoi juger sur pièce sans rouvrir un
fichier de plusieurs gigaoctets.


## Dans quoi ça cherche : les archives sont ouvertes

Un fichier comprimé n'est pas lu comme un bloc opaque. Sont décompressés, le
temps de la recherche seulement :

| forme | ce que c'est |
|---|---|
| `.gz` | en flux, sans jamais le charger — c'est le cas des chaînes de disque |
| `.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp`, `.epub`, `.jar`, `.apk` | un zip : chaque membre passe sous les motifs |
| `.pdf` | les flux `FlateDecode` sont décomprimés. Le but n'est pas de rendre le PDF lisible — cela demanderait une bibliothèque — mais que ses octets décompressés passent sous les motifs. Un mot de passe écrit dans un PDF y devient visible ; sa mise en page, non |
| `.bz2`, `.xz`, `.lzma`, `.zst` | en flux. `zstd` demande Python 3.14 ou le paquet `zstandard` ; quand ni l'un ni l'autre n'est là, un fait `limite` le dit plutôt que de laisser le fichier passer pour illisible |

C'est ce qui compte le plus pour `PHOTOREC/` : ce que photorec rend d'un
traitement de texte est un `.docx`, et sans décompression les motifs n'y
verraient rien alors que le texte est bien là.

**La même lecture s'applique aux membres d'archive**, pas seulement aux fichiers
posés sur le disque : un `syslog.2.gz` rangé dans `JOURNAUX/…_var_log.tar.gz`
est décomprimé avant d'être soumis aux motifs. Sans cela, une chaîne présente
dans un journal tourné ressortait **ABSENTE** de la collecte — et c'est là que
`collecte-linux` range la plus grande partie des journaux.

**L'empreinte porte sur le fichier tel qu'il est sur le disque**, jamais sur
son contenu décompressé : un `sha256:` d'indicateur se compare bien au fichier
qu'on lui a donné.

**Le plafond est de 256 Mo décompressés par fichier.** Ce n'est pas une
précaution de style : une archive peut se décompresser en téraoctets (*zip
bomb*), et une collecte forensique est justement l'endroit où l'on trouve des
fichiers hostiles. Au-delà, la lecture s'arrête et un fait `limite` le dit —
« archive lue en partie » — parce qu'un document qu'on n'a pas su ouvrir
entièrement ne doit pas ressembler à un document sans rien dedans.


## Reprendre après un plantage

Le parcours des indicateurs est la partie longue de l'extraction : il lit
chaque octet de la collecte, décompresse des gigaoctets de chaînes, ouvre
chaque archive. Sur un gros dossier, c'est des heures.

**Et il a lieu à chaque extraction**, même sans `--indicateurs` : la liste que
l'outil cherche de lui-même suffit à le déclencher. C'est voulu — un secret qui
traîne dans l'espace libre ne doit pas dépendre de ce que l'analyste a pensé à
demander —, mais cela veut dire qu'une extraction coûte ce parcours, et c'est
précisément ce que le journal ci-dessous amortit.

Un journal `<sortie>-reprise.jsonl` note, **fichier par fichier**, ce qui a été
parcouru et ce que cela a produit. Il est vidé sur le disque après chaque
fichier : un plantage ne coûte que le fichier en cours.

Pour reprendre, relancez **la même commande**. Un fichier dont la taille et la
date n'ont pas bougé n'est pas relu : ses faits sont rejoués tels quels. Les
scellés étant montés en lecture seule, ces deux critères suffisent — et s'ils
bougent, c'est que la collecte a changé, auquel cas il faut relire.

Le résultat est **identique à un passage d'un seul tenant, identifiants
compris** : le parcours est trié, donc les faits rejoués retombent sur les
mêmes numéros. C'est vérifié par le test, qui coupe le journal en plein milieu
d'une ligne — ce que fait un plantage réel — et compare les deux sorties.

Le journal porte l'empreinte de la **provenance** : l'extracteur lui-même, la
collecte, et les listes de recherche données. Changer l'un des trois l'invalide
— les faits d'avant répondaient à d'autres questions, ou sortaient d'un autre
code. `--sans-reprise` force un parcours complet.

C'est la **même** valeur que le manifeste publie, sous `provenance_sha256`, et
que l'annexe du rapport reprend avec l'empreinte de chaque liste : deux
extractions qui portent la même provenance ont posé les mêmes questions au même
outil sur la même collecte.


## Une simple liste de chaînes : `--textes`

Le fichier d'indicateurs demande `type: valeur` et refuse le reste. C'est bien
pour mêler empreintes, adresses et expressions, mais lourd quand on n'a qu'une
liste — des noms, des références de dossier, des mots-clés d'affaire.

    python3 extraire.py <collecte> -o faits.jsonl --textes mots-cles.txt

Une ligne, une chaîne. Rien d'autre :

    # mots-clés de l'affaire
    Dupont (RH)
    DOSSIER-2026-114
    Bienvenue2025!        # le mot de passe du brouillon

Les lignes vides et celles qui commencent par `#` sont ignorées ; un `#` en fin
de ligne sert d'étiquette, comme dans le fichier d'indicateurs. L'option est
répétable, et se combine avec `--indicateurs`.

Les chaînes sont cherchées **à la lettre**, sans tenir compte de la casse, et
**jamais** comme une expression rationnelle : qui écrit `Dupont (RH)` veut ces
caractères-là, pas un groupe de capture. Pour une expression, utilisez
`regex:` dans un fichier d'indicateurs.

**Ne posez pas ce fichier dans la collecte** : il s'y trouverait lui-même,
chaque chaîne y figurant par construction. L'extracteur écarte le fichier qu'on
lui donne, mais pas une copie qu'on aurait laissée ailleurs dans le dossier.

### Pourquoi une chaîne imbriquée dans une autre ressort quand même

Les octets ne sont lus qu'**une fois**, mais chaque motif est cherché
**séparément** sur ce qui défile. Regrouper les motifs en une seule alternation
ne rendrait que des correspondances qui ne se chevauchent pas : le motif interne
« mot de passe en clair », qui reconnaît `password = Bienvenue2025!`, avalerait
`Bienvenue2025!`, et la chaîne demandée ressortirait **ABSENTE** — on
annoncerait à l'analyste que sa preuve n'existe pas alors qu'elle est là.

Des passes séparées ne peuvent pas se voler une correspondance : la question ne
se pose plus. Et c'est aussi le plus rapide, à rebours de l'intuition, parce que
`re` ne sait pas préfiltrer une alternation, dont le coût croît avec le nombre
de branches. Mesuré sur 8 Mo de texte sans aucune correspondance :

| motifs cherchés | passes séparées | une alternation |
|---|---|---|
| 11 (ceux de l'outil) | 1,0 s | 1,9 s |
| 61 (+ un `--textes` de 50 lignes) | 2,7 s | 22,6 s |
| 211 (+ un `--textes` de 200 lignes) | 7,9 s | 174 s |

C'est le troisième cas qui compte : une liste de deux cents noms est exactement
ce pour quoi `--textes` existe.
