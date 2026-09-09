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
