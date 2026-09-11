#!/usr/bin/env bash
# Garde des scellés — hook PreToolUse de Crush.
#
# Crush appelle ce script avant chaque outil que crush.json lui confie (edit,
# write, multiedit, bash), avec sur l'entrée standard un JSON :
# { "tool_name", "tool_input", "cwd", … }. Sortir avec le code 2 BLOQUE
# l'appel, et ce qui est écrit sur stderr revient au modèle comme motif.
#
# UN SCELLÉ SE RECONNAÎT À SA STRUCTURE, PAS À SON CHEMIN. C'est tout le
# principe de ce script. Un chemin écrit en dur — /mnt/scelles ou un autre —
# ne protège rien sur un poste où la collecte est ailleurs, tout en ayant
# l'air de marcher : c'est le pire état possible pour une ceinture de sécurité.
# Ici, un dossier qui porte au moins trois des dossiers que collecte-linux.conf
# écrit EST une collecte, où qu'il soit posé, et le reste sans qu'on ait rien
# à déclarer.
#
# Ce qui est refusé : écrire dans un scellé, ou y toucher par une commande
# quelconque. Ce qui est AUTORISÉ : lancer les scripts du skill dessus — ils
# ne modifient jamais leur entrée, c'est leur invariant et les tests le
# vérifient. Sans cette autorisation la garde refuserait la toute première
# commande du skill, qui doit bien lire la collecte pour en tirer des faits.
#
# DEUXIÈME CAS, RÉGLÉ AUTREMENT : l'IMAGE MONTÉE. Quand la collecte ne porte
# pas ce qu'il faut, l'analyse doit pouvoir aller le chercher sur l'image
# elle-même, montée en lecture seule à côté — « mnt/ » par convention, ou
# l'endroit que l'analyste indique. Là, tout ce qui LIT est permis, y compris
# par bash : cat, strings, sqlite3, tar -t, find… Seul l'ÉCRITURE est refusée.
# Une image se reconnaît elle aussi à sa structure — une racine Linux porte
# etc/ et usr/ — et jamais à son chemin, pour la même raison que le scellé.
#
# Ce qu'il ne remplace pas : le montage en lecture seule (mount -o bind,ro),
# qui est la seule garantie réelle. Ceci est une ceinture de plus, lisible,
# qui explique au modèle pourquoi il ne peut pas.
#
# Réglage FACULTATIF : des dossiers à protéger EN PLUS, un par ligne. Sans ces
# fichiers, la reconnaissance par structure suffit — c'est le cas courant.
# TROIS emplacements sont lus, et leurs listes s'AJOUTENT. Posez le fichier où
# vous voulez parmi ceux-là, « --essai » dira lequel il a trouvé :
#
#   <à côté de ce script>/scelles.txt   soit <affaire>/outils/scelles.txt
#   <dossier d'analyse>/scelles.txt     à la racine de l'affaire
#   ~/.config/crush/scelles.txt         ce qui vaut pour tout le poste
#
# ($XDG_CONFIG_HOME remplace ~/.config s'il est posé, comme pour Crush.)
#
# Le premier est repéré par le chemin du SCRIPT, pas par le dossier courant :
# c'est le seul qui tienne quand on lance la garde à la main depuis ailleurs.
# Le deuxième vient de CRUSH_PROJECT_DIR, que Crush pose, avec $PWD à défaut —
# Crush lance bien le hook dans le dossier du projet, mais rien d'autre ne le
# garantit. Mesuré : « $PWD/outils/scelles.txt » est LU sous Crush et
# INTROUVABLE dès qu'on appelle le script depuis /tmp ; l'ancrage sur le
# script est lu dans les deux cas. N'écrivez donc jamais « ./scelles.txt ».
#
# CRUSH_SCELLES remplace les trois, et accepte plusieurs chemins séparés par
# « : », comme PATH.

set -u

# ÉCHOUER FERMÉ. Un hook qui sort autrement que 2 laisse passer l'appel : sans
# python3, la garde s'ouvrait en silence — elle avait l'air d'être là et ne
# refusait plus rien. Mieux vaut bloquer et le dire.
if ! command -v python3 >/dev/null 2>&1; then
    echo "refusé : python3 est introuvable, la garde des scellés ne peut pas" \
         "s'exécuter. Tant qu'elle ne peut pas juger, rien n'écrit." >&2
    exit 2
fi

_scelles_defaut() {
    local ici
    ici=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || ici="."
    printf '%s:%s:%s' "$ici/scelles.txt" \
                      "${CRUSH_PROJECT_DIR:-$PWD}/scelles.txt" \
                      "${XDG_CONFIG_HOME:-$HOME/.config}/crush/scelles.txt"
}
export TK_SCELLES="${CRUSH_SCELLES:-$(_scelles_defaut)}"

# Le programme est capturé dans une variable, et NON passé sur l'entrée
# standard : celle-ci porte le JSON de Crush, et un « python3 - » la mangerait.
garde=$(cat <<'PY'
import json, os, re, sys

# Les dossiers que collecte-linux.conf écrit sous PREFIX/.
DOSSIERS = {"SYSTEME", "PAQUETS", "COMPTES", "CONNEXIONS", "RESEAU",
            "PERSISTANCE", "JOURNAUX", "TIMELINE", "MACHINES", "SUPPRIMES",
            "PHOTOREC", "STRINGS", "PLASO"}
# Trois, et non un : un dossier qui s'appellerait « RESEAU » sans être une
# collecte ne doit pas geler le poste de l'analyste.
ASSEZ = 3

# Une racine Linux montée. « etc » et « usr » sont exigés tous les deux, plus
# cinq marqueurs en tout : un arbre de compilation qui porterait bin/ et lib/
# ne doit pas geler le poste. La racine « / » du poste d'analyse est écartée
# explicitement — sans quoi la garde refuserait absolument tout.
RACINE = {"etc", "usr", "var", "bin", "sbin", "lib", "lib64", "boot", "home",
          "root", "opt", "srv", "proc", "sys", "dev", "tmp", "run", "mnt", "media"}
ASSEZ_RACINE = 5

# Les commandes qui ÉCRIVENT. La garde ne les cherche qu'en tête de segment —
# après un « ; », un « && », un tube — et non n'importe où : « grep -r "rm "
# mnt/ » est une lecture parfaitement légitime.
MUTENT = {"rm", "rmdir", "mv", "cp", "touch", "mkdir", "rename", "chmod",
          "chown", "chgrp", "ln", "dd", "truncate", "tee", "install", "rsync",
          "shred", "unzip", "gunzip", "bunzip2", "unxz", "mkfs", "fsck",
          "mount", "umount", "patch", "split", "wipefs", "sgdisk", "fdisk",
          "debugfs", "tune2fs", "xfs_undelete", "photorec", "testdisk"}
SEPARATEURS = re.compile(r'\|\||&&|[;|&\n\r]')
# Une redirection, avec son descripteur facultatif : « > x », « >x », « 2>> x ».
# On NORMALISE avant de lire, plutôt que de découper à l'indice : « cat a>b »,
# collé à un mot non numérique, n'était pas vu du tout.
REDIRECTION = re.compile(r'\d?>{1,2}')
# « sed -i », « tar -x », « perl -i » : la commande est anodine, le drapeau non.
DRAPEAUX_ECRIVENT = {"-i", "--in-place", "-x", "--extract", "--delete"}

# Les scripts du skill ne modifient JAMAIS leur entrée : ils lisent les
# archives en flux, sans les dépaqueter, et écrivent là où « -o » le dit.
#
# La commande doit COMMENCER par l'un d'eux. Chercher leur nom n'importe où
# dans la ligne ne valait rien : « cp /etc/hosts SCELLE/SYSTEME/hostname
# # extraire.py » passait, et détruisait la pièce. Le mot magique en
# commentaire suffisait à tout blanchir.
RE_LECTEUR = re.compile(r'\s*(?:[\w./-]*python[\d.]*\s+)?[\w./-]*'
                        r'(?:extraire|controles|brouillon)\.py(?=\s|$)')
# Tout ce qui peut remettre une commande derrière la première, ou rediriger.
# « & » et le saut de ligne manquaient ; « # » aussi, et c'était le trou.
ENCHAINE = (";", "&", "|", ">", "<", "`", "$(", "#", "\n", "\r", "\\")
# Où le lecteur ÉCRIT. Un « -o » qui vise le scellé n'est pas une redirection
# au sens du shell, donc rien ne l'arrêtait — alors que c'est la façon la plus
# naturelle d'y écrire par mégarde.
SORTIES = ("-o", "--sortie", "--out")


_VUS = {}


def _noms(d):
    """Le contenu d'un dossier, mémorisé. Une commande bash porte des dizaines
    de mots, dont chacun fait remonter tous ses parents : sans ce cache, la
    garde relit les mêmes dossiers des centaines de fois, et le hook a cinq
    secondes."""
    if d not in _VUS:
        try:
            _VUS[d] = set(os.listdir(d))
        except OSError:
            _VUS[d] = set()
    return _VUS[d]


def est_collecte(d):
    noms = _noms(d)
    return sum(1 for x in noms & DOSSIERS
               if os.path.isdir(os.path.join(d, x))) >= ASSEZ


def est_image(d):
    if d == os.sep:
        return False
    noms = _noms(d)
    return {"etc", "usr"} <= noms and len(noms & RACINE) >= ASSEZ_RACINE


def absolu(chemin, cwd=None):
    p = os.path.expanduser(chemin)
    return os.path.abspath(os.path.join(cwd, p)
                           if cwd and not os.path.isabs(p) else p)


def sous(p, d):
    """Ce chemin est-il DANS ce dossier ?"""
    return p == d or p.startswith(d + os.sep)


def protege(chemin, declares, cwd=None):
    """(« scelle » ou « image », dossier) que ce chemin vise, ou (None, None).

    On remonte les parents : écrire un fichier NEUF au fond d'une collecte doit
    être refusé comme le reste."""
    p = absolu(chemin, cwd)
    for d in declares:
        if sous(p, d):
            return "scelle", d
    while True:
        if est_collecte(p):
            return "scelle", p
        if est_image(p):
            return "image", p
        parent = os.path.dirname(p)
        if parent == p:
            return None, None
        p = parent


def ecrit_dans(commande, dossier, cwd=None):
    """La commande écrit-elle DANS ce dossier ? Segment par segment.

    Une image montée se lit librement — c'est tout l'intérêt d'aller y chercher
    ce qui manque à la collecte. Seule l'écriture est refusée, et elle prend
    trois formes : une redirection dont la CIBLE est dedans, une commande qui
    modifie ses arguments, ou un drapeau qui transforme une lecture en
    écriture.
    """
    def dedans(mot):
        return sous(absolu(mot.strip("'\""), cwd), dossier)

    for segment in SEPARATEURS.split(commande):
        # « cat a>b » devient « cat a > b » : une seule forme à examiner
        # ensuite, au lieu d'une arithmétique d'indices qui laissait justement
        # passer la redirection collée à un mot non numérique.
        mots = REDIRECTION.sub(lambda m: f" {m.group(0)} ", segment).split()
        if not mots:
            continue
        for op, cible in zip(mots, mots[1:]):
            if REDIRECTION.fullmatch(op) and dedans(cible):
                return True
        # le premier mot du segment, une fois les « VAR=valeur » écartés
        tete = next((os.path.basename(m) for m in mots if "=" not in m.split("/")[0]),
                    "")
        args = [m for m in mots[1:]
                if not m.startswith("-") and not REDIRECTION.fullmatch(m)]
        if (tete in MUTENT or DRAPEAUX_ECRIVENT & set(mots)) \
                and any(dedans(m) for m in args):
            return True
    return False


e = json.load(sys.stdin)
outil = str(e.get("tool_name") or "").lower()
entree = e.get("tool_input") or {}
# Le dossier de travail : sans lui, « rm -rf PC01_… » depuis le dossier parent
# n'était même pas vu comme un chemin.
cwd = e.get("cwd") if isinstance(e.get("cwd"), str) else None

# Plusieurs fichiers, séparés comme PATH : celui de l'affaire et celui du
# poste s'AJOUTENT. Un seul chemin fonctionne toujours — c'est une liste à un
# élément. Un fichier absent n'est pas une erreur : la reconnaissance par
# structure reste le cas courant.
declares = []
lus = set()
for f in os.environ.get("TK_SCELLES", "").split(os.pathsep):
    # Les trois emplacements se recouvrent quand le script est à la racine de
    # l'affaire : le même fichier serait alors lu deux fois.
    if not f or f in lus:
        continue
    lus.add(f)
    # Un chemin RELATIF se lit depuis le dossier du FICHIER qui le porte, et
    # non depuis le dossier courant du processus. C'est la seule règle qui ne
    # surprenne pas : dans <affaire>/outils/scelles.txt, « ../scelle » désigne
    # <affaire>/scelle, que la garde soit lancée par Crush ou à la main depuis
    # n'importe où. Résolu contre le dossier courant, le même « ../scelle »
    # aurait désigné un dossier différent à chaque appel — et n'aurait rien
    # protégé, sans un mot.
    base = os.path.dirname(os.path.abspath(f))
    try:
        with open(f, encoding="utf-8") as fh:
            for ligne in fh:
                ligne = ligne.strip()
                if not ligne or ligne.startswith("#"):
                    continue
                ligne = os.path.expanduser(ligne.rstrip("/"))
                declares.append(os.path.abspath(
                    ligne if os.path.isabs(ligne) else os.path.join(base, ligne)))
    except OSError:
        pass

# « --essai » demande ce que la garde a VRAIMENT retenu : les listes lues, et
# les dossiers qu'elles désignent une fois résolus. Un fichier posé au mauvais
# endroit, ou un « ../scelle » qui ne tombe pas où l'on croit, ne se devine
# pas — et c'est le même code qui répond, pas une seconde lecture en Bash.
if os.environ.get("TK_LISTER"):
    for d in declares:
        if not os.path.isdir(d):
            print("  DÉCLARÉ MAIS ABSENT : " + d)
            continue
        print("  déclaré : " + d)
        # Déclarer un dossier le rend STRICT — le régime du scellé. Sur une
        # image montée, c'est une perte : la garde y laisse normalement TOUT
        # ce qui lit, y compris par bash, et c'est l'intérêt même de l'avoir
        # montée. La déclaration prime sur la reconnaissance par structure ;
        # autant que ce soit un choix, et pas une surprise.
        if est_image(d):
            print("      ↑ c'est une IMAGE, reconnue à sa structure. La "
                  "déclarer la rend STRICTE :")
            print("        plus de cat, strings ni sqlite3 par bash dessus. "
                  "Retirez-la de la liste")
            print("        pour garder la lecture libre.")
        elif est_collecte(d):
            print("      ↑ c'est déjà une COLLECTE, reconnue à sa structure : "
                  "la déclarer")
            print("        n'ajoute rien.")
    sys.exit(0 if all(os.path.isdir(d) for d in declares) else 1)

commande = entree.get("command") if isinstance(entree.get("command"), str) else ""
vises = [v for k in ("file_path", "path") for v in (entree.get(k),) if isinstance(v, str)]
# TOUT mot d'une commande est un chemin possible : un nom sans barre oblique
# en est un, relatif au dossier de travail. Les redirections sont DÉCOLLÉES
# d'abord : « cat a>/scelle/x » ne formait qu'un seul mot, qui ne ressemblait à
# aucun chemin, et le scellé n'était donc même pas vu.
mots = [t.strip("'\"") for t in REDIRECTION.sub(
    lambda m: f" {m.group(0)} ", commande).split()]
vises += [m for m in mots
          if m and not m.startswith("-") and not REDIRECTION.fullmatch(m)]

# UN seul parcours des mots : protege() remonte les parents, et le faire deux
# fois doublait ce travail sur une commande bash qui porte désormais tous ses
# mots. Le scellé d'abord : c'est le régime le plus strict, et un scellé posé
# sous un point de montage doit être traité en scellé.
genres = [protege(c, declares, cwd) for c in vises]
touche = next((d for g, d in genres if g == "scelle"), None)

if touche:
    if outil == "bash" and RE_LECTEUR.match(commande) \
            and not any(d in commande for d in ENCHAINE) \
            and not any(protege(v, declares, cwd)[0] == "scelle"
                        for o, v in zip(mots, mots[1:]) if o in SORTIES):
        sys.exit(0)      # un lecteur du skill, seul, qui écrit hors du scellé

    print(f"refusé : « {touche} » est un scellé — une collecte, reconnue à sa "
          "structure. Le skill ne modifie jamais une pièce. Pour LIRE, servez-vous "
          "de view, grep, ls, ou lancez extraire.py / controles.py dessus (seuls, "
          "sans redirection ni enchaînement) ; le rapport et les fichiers de "
          "travail vont dans le dossier d'analyse, hors du scellé.", file=sys.stderr)
    sys.exit(2)

# L'image montée : tout ce qui lit est permis, rien de ce qui écrit.
image = next((d for g, d in genres if g == "image"), None)
if not image:
    sys.exit(0)

if outil in ("edit", "write", "multiedit", "download", "lsp_rename",
             "lsp_replace_symbol") or (outil == "bash"
                                       and ecrit_dans(commande, image, cwd)):
    print(f"refusé : « {image} » est l'IMAGE EXAMINÉE, montée en lecture seule. "
          "Vous pouvez y LIRE tout ce que vous voulez — cat, strings, file, "
          "stat, find, grep, sqlite3, tar -t — et c'est même ce qu'il faut "
          "faire quand la collecte ne porte pas la pièce cherchée. Mais rien "
          "n'y est écrit, jamais : dirigez la sortie vers le dossier d'analyse. "
          "Notez dans le rapport que la pièce vient de l'image et non de la "
          "collecte : elle n'a pas d'empreinte au manifeste.", file=sys.stderr)
    sys.exit(2)

sys.exit(0)
PY
)

# ── « --essai » : la garde se contrôle elle-même ──────────────────────
# Un « code 2 » tapé à la main ne prouve rien : il suffit d'une faute de
# frappe dans le chemin — « scelles » pour « scelle », un cwd qui n'est
# pas le dossier d'analyse — pour viser un dossier INEXISTANT. La garde
# rend alors 0, très correctement, et on lit « la garde ne mord pas »
# alors qu'elle n'a rien eu à mordre. L'inverse est pire encore : un
# chemin mal tapé qui tombe par hasard sur un scellé rassure à tort.
# Ici, rien à taper : on sonde CHAQUE sous-dossier avec le vrai
# programme, et on dit ce que la garde répond de chacun.
if [ "${1:-}" = "--essai" ]; then
    dossier=$(cd "${2:-.}" 2>/dev/null && pwd) || {
        echo "essai : « ${2:-.} » n'est pas un dossier" >&2; exit 1; }
    # Les listes déclarées suivent le dossier EXAMINÉ, pas le dossier courant :
    # « --essai ~/analyse/PC01 » depuis ailleurs doit lire le scelles.txt de
    # PC01, sinon l'essai ne dit pas la vérité sur ce dossier-là.
    export TK_SCELLES="${CRUSH_SCELLES:-$dossier/outils/scelles.txt:$dossier/scelles.txt:${XDG_CONFIG_HOME:-$HOME/.config}/crush/scelles.txt}"
    motif=$(mktemp)
    trap 'rm -f "$motif"' EXIT

    demander() {   # $1 = outil, $2 = chemin visé, $3 = commande bash
        printf '{"tool_name":"%s","tool_input":{"file_path":"%s","command":"%s"},"cwd":"%s"}' \
            "$1" "$2" "$3" "$dossier" | python3 -c "$garde" 2>"$motif"
    }
    regime() {     # le mot que la garde emploie pour ce dossier
        demander write "$1" "" && { echo libre; return; }
        grep -q "est un scellé" "$motif" && { echo scelle; return; }
        grep -q "IMAGE EXAMINÉE" "$motif" && { echo image; return; }
        echo refuse
    }

    printf 'garde des scellés — essai sur %s\n' "$dossier"
    lues=0
    IFS=: read -ra _listes <<< "$TK_SCELLES"
    for f in "${_listes[@]}"; do
        [ -f "$f" ] && { printf '  liste lue : %s\n' "$f"; lues=1; }
    done
    if [ "$lues" -eq 0 ]; then
        printf '  aucune liste déclarée — la structure suffit\n'
    else
        # C'est le programme lui-même qui dit ce qu'il a retenu : les chemins
        # relatifs y sont résolus une seule fois, au même endroit que pour un
        # vrai appel.
        if ! printf '{"tool_name":"view","tool_input":{},"cwd":"%s"}' "$dossier" \
                | TK_LISTER=1 python3 -c "$garde"; then
            souci=1
        fi
    fi
    echo
    scelles=0 images=0 souci=0
    for d in "$dossier"/*/; do
        [ -d "$d" ] || continue
        nom=$(basename "$d")
        case "$(regime "$d")" in
          scelle) scelles=$((scelles + 1))
                  printf '  %-22s SCELLÉ   écriture refusée' "$nom/"
                  if demander bash "" "grep -r motif $d"; then
                      printf '  — mais bash y lit, ANORMAL\n'; souci=1
                  else printf ', bash refusé aussi\n'; fi ;;
          image)  images=$((images + 1))
                  printf '  %-22s IMAGE    écriture refusée' "$nom/"
                  if demander bash "" "cat ${d}etc/os-release"; then
                      printf ', lecture libre\n'
                  else printf '  — mais la LECTURE est refusée, ANORMAL\n'; souci=1; fi ;;
          *)      printf '  %-22s libre    dossier de travail\n' "$nom/" ;;
        esac
    done
    # Le dossier lui-même doit rester écrivable : une garde qui refuse tout
    # est aussi cassée qu'une garde qui ne refuse rien — le rapport ne
    # pourrait plus s'y écrire.
    if demander write "$dossier/rapport-forensic.md" ""; then
        printf '  %-22s libre    le rapport peut y être écrit\n' "./"
    else
        printf '  %-22s REFUSÉ   le rapport ne peut PAS y être écrit\n' "./"
        souci=1
    fi

    echo
    if [ "$scelles" -eq 0 ]; then
        echo "AUCUN SCELLÉ RECONNU — rien n'est protégé ici."
        echo "Un scellé se reconnaît à sa STRUCTURE : au moins trois des"
        echo "dossiers de collecte. Vérifiez le montage — « ls scelle/ » doit"
        echo "montrer SYSTEME/, COMPTES/, JOURNAUX/…"
        exit 1
    fi
    [ "$images" -eq 0 ] && echo "note : aucune image montée ici, c'est permis."
    if [ "$souci" -ne 0 ]; then
        echo "LA GARDE SE COMPORTE MAL — voyez les lignes ANORMAL ci-dessus."
        exit 1
    fi
    echo "la garde mord."
    exit 0
fi

python3 -c "$garde"
