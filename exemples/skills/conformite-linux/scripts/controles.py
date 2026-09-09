#!/usr/bin/env python3
"""Relève des CONSTATS objectifs dans une collecte, pour les confronter à une charte.

    controles.py <dossier de collecte> [-o constats.jsonl]
    controles.py <dossier de collecte> --regles usage.regles --faits faits.jsonl

Un constat n'est pas un manquement. « PermitRootLogin yes » est un fait ; qu'il
soit interdit dépend de la charte, que ce script ne connaît pas. Le rapprochement
est le travail du rapport, et il doit être visible.

Chaque constat porte donc : ce qui est observé, où, par quel geste, et la
question à laquelle une règle devra répondre pour en faire un manquement.

Avec --regles, les règles écrites à la main dans un fichier .regles sont
cherchées dans la collecte : le constat porte alors le numéro de la règle, et
la question devient celle de la traduction — l'indice retenu dit-il bien ce que
la règle dit ? Voir references/regles/ pour le format.

Les dates des constats sont en UTC (suffixe Z) quand la pièce les donne en
epoch, et telles que la pièce les écrit sinon (dpkg.log : heure du poste, sans
fuseau). C'est le brouillon du rapport qui les met dans le fuseau du poste.

Sorties : constats.jsonl (un constat par ligne, pour un SIEM), constats.csv
(les mêmes colonnes, pour un tableur), constats-manifeste.json (empreintes).

Bibliothèque standard seulement. La collecte n'est jamais modifiée.
"""
import argparse, base64, collections, csv, hashlib, json, os, re, sys, tarfile
from datetime import datetime, timezone

CONSTATS = []
_N = [0]
SANS_REGLE = ("limite", "conforme")      # thèmes qui ne sont pas des constats de manquement
COLONNES_CSV = ("id", "theme", "regle", "constat", "valeur", "date", "acteur", "portee",
                "source", "methode", "question", "note")


RE_CONTROLE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _propre(v):
    """Une valeur tirée d'une pièce peut porter des octets de contrôle — un
    contexte pris dans une base binaire, un nom de fichier forgé. Ils n'ont
    rien à faire dans un rapport, un CSV ou un terminal : un point médian."""
    return RE_CONTROLE.sub("·", v) if isinstance(v, str) else v


def constat(theme, quoi, valeur, source, methode, acteur=None, portee=None,
            question=None, note=None, regle=None, date=None):
    """Pose un constat.

    theme    la famille : comptes, authentification, secrets, durcissement, usage
    quoi     ce qui est observé, formulé sans jugement
    portee   « poste » ou « compte » — un manquement de poste n'est imputable
             à personne en particulier
    question ce qu'une règle devra dire pour en faire un manquement ; quand la
             règle est fournie, ce que sa traduction en indice suppose
    regle    l'identifiant de la règle cherchée, quand il y en a une
    date     l'horodatage porté par la pièce elle-même, quand elle en porte un
    """
    _N[0] += 1
    c = {"id": f"C{_N[0]:04d}", "theme": theme, "constat": quoi, "valeur": _propre(valeur),
         "source": source, "methode": methode,
         "portee": portee or ("compte" if acteur else "poste")}
    for k, v in (("regle", regle), ("acteur", acteur), ("date", date),
                 ("question", question), ("note", _propre(note))):
        if v is not None:
            c[k] = v
    CONSTATS.append(c)
    return c


def _epoch_iso(n):
    return datetime.fromtimestamp(n, timezone.utc).isoformat().replace("+00:00", "Z")


def _compte_de(chemin, suffixe):
    """PREFIX_<compte>_<suffixe> → compte."""
    m = re.search(rf'_([^_]+)_{re.escape(suffixe)}$', os.path.basename(chemin))
    return m.group(1) if m else "?"


class Collecte:
    def __init__(self, racine):
        self.racine = os.path.abspath(racine)
        self.prefix = os.path.basename(self.racine)
        self.lus = set()
        if not os.path.isdir(self.racine):
            sys.exit(f"pas un dossier : {self.racine}")

    def rel(self, chemin):
        return os.path.relpath(chemin, self.racine)

    def chercher(self, motif, sous=None):
        base = os.path.join(self.racine, sous) if sous else self.racine
        t = []
        for d, _, fichiers in os.walk(base):
            t += [os.path.join(d, n) for n in fichiers if motif in n]
        return sorted(t)

    def un(self, motif, sous=None):
        t = self.chercher(motif, sous)
        return t[0] if t else None

    def texte(self, chemin, limite=8_000_000):
        try:
            with open(chemin, "rb") as fh:
                self.lus.add(chemin)
                return fh.read(limite).decode("utf-8", "replace")
        except OSError:
            return ""

    def membres_tar(self, archive, garde=None):
        """(nom, contenu) des fichiers d'un .tar.gz — ceux que garde(nom) accepte.

        Le filtre passe AVANT la lecture : une archive de profils porte des
        caches de centaines de Mo qu'aucun contrôle ne regarde.
        """
        self.lus.add(archive)
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m in t:
                    if not m.isfile():
                        continue
                    nom = m.name[2:] if m.name.startswith("./") else m.name
                    if garde and not garde(nom):
                        continue
                    fh = t.extractfile(m)
                    if fh is not None:
                        yield nom, fh.read()
        except (tarfile.TarError, OSError, EOFError) as e:
            print(f"  ! {os.path.basename(archive)} : {e}", file=sys.stderr)


# ── 1 · comptes et mots de passe ─────────────────────────────────────
RE_SUDO_TOUT = re.compile(r'^\s*%?\S+\s+ALL\s*=\s*\(\s*ALL(\s*:\s*ALL)?\s*\)\s*ALL\s*$')


def comptes(c):
    p = c.un("passwd", "COMPTES")
    homes = {}
    if p:
        for l in c.texte(p).splitlines():
            ch = l.split(":")
            if len(ch) < 7 or not ch[2].isdigit():
                continue
            nom, uid, home, shell = ch[0], int(ch[2]), ch[5], ch[6]
            if uid == 0 and nom != "root":
                constat("comptes", "compte disposant des droits de root",
                        f"{nom} (uid 0)", c.rel(p), "champ 3 de /etc/passwd",
                        acteur=nom,
                        question="la charte autorise-t-elle un second compte "
                                 "administrateur, et celui-ci est-il déclaré ?")
            if uid >= 1000 and not shell.endswith(("nologin", "false")):
                homes.setdefault(home, []).append(nom)
    for home, noms in sorted(homes.items()):
        if len(noms) > 1:
            constat("comptes", "plusieurs comptes partagent le même dossier",
                    f"{', '.join(sorted(noms))} → {home}", c.rel(p),
                    "regroupement du champ 6 de /etc/passwd",
                    question="la charte impose-t-elle un compte nominatif par "
                             "personne ? Un dossier partagé rend toute "
                             "attribution incertaine.")

    d = c.un("_droits.tar.gz", "COMPTES")
    if not d:
        return
    for nom, blob in c.membres_tar(d):
        txt = blob.decode("utf-8", "replace")
        base = os.path.basename(nom)
        if base == "shadow":
            for l in txt.splitlines():
                ch = l.split(":")
                if len(ch) < 8:
                    continue
                qui, hache, expire = ch[0], ch[1], ch[4]
                if hache == "":
                    constat("authentification", "compte sans mot de passe", qui,
                            f"{c.rel(d)} → {nom}", "champ 2 vide dans /etc/shadow",
                            acteur=qui,
                            question="la charte exige-t-elle un mot de passe sur "
                                     "tout compte ouvrant une session ?")
                elif hache.startswith("$1$"):
                    constat("authentification",
                            "mot de passe haché en MD5 (algorithme obsolète)", qui,
                            f"{c.rel(d)} → {nom}", "préfixe $1$ dans /etc/shadow",
                            acteur=qui,
                            question="la charte fixe-t-elle un algorithme minimal ?")
                if expire in ("", "99999") and hache not in ("", "*", "!", "!!"):
                    constat("authentification", "mot de passe sans expiration", qui,
                            f"{c.rel(d)} → {nom}", "champ 5 de /etc/shadow",
                            acteur=qui,
                            question="la charte impose-t-elle un renouvellement "
                                     "périodique ?")
        elif base == "sudoers" or "/sudoers.d/" in nom:
            for l in txt.splitlines():
                l = l.strip()
                if not l or l.startswith("#"):
                    continue
                if "NOPASSWD" in l:
                    constat("authentification",
                            "élévation sans mot de passe (sudo NOPASSWD)", l[:120],
                            f"{c.rel(d)} → {nom}", "grep NOPASSWD dans sudoers",
                            question="la charte tolère-t-elle un sudo sans "
                                     "ressaisie du mot de passe ?")
                if RE_SUDO_TOUT.search(l):
                    constat("authentification", "droits root complets accordés",
                            l[:120], f"{c.rel(d)} → {nom}",
                            "règle « ALL=(ALL) ALL » dans sudoers",
                            note="courant et souvent légitime — à confronter à la "
                                 "liste des administrateurs déclarés")
        elif base == "config" and "selinux" in nom:
            m = re.search(r'^\s*SELINUX\s*=\s*(\w+)', txt, re.M)
            if m and m.group(1).lower() != "enforcing":
                constat("durcissement", "SELinux n'est pas en mode strict",
                        m.group(1), f"{c.rel(d)} → {nom}",
                        "grep SELINUX= dans /etc/selinux/config",
                        question="la charte impose-t-elle le maintien des "
                                 "protections du système ?")
        elif base == "login.defs":
            m = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', txt, re.M)
            if m and int(m.group(1)) > 365:
                constat("authentification",
                        "durée de vie des mots de passe très longue",
                        f"PASS_MAX_DAYS {m.group(1)}", f"{c.rel(d)} → {nom}",
                        "grep PASS_MAX_DAYS dans /etc/login.defs",
                        question="la charte fixe-t-elle une durée maximale ?")


# ── 2 · le serveur SSH, le pare-feu, les réseaux sans fil ────────────
# Une seule lecture de l'archive réseau : les constats de durcissement et la
# liste des réseaux sans fil (pour les règles) en sortent ensemble.
SSHD = [
    ("PermitRootLogin", ("yes", "without-password", "prohibit-password"),
     "connexion directe en root autorisée par SSH",
     "la charte interdit-elle la connexion directe au compte root ?"),
    ("PasswordAuthentication", ("yes",),
     "authentification SSH par mot de passe autorisée",
     "la charte impose-t-elle l'authentification par clé ?"),
    ("PermitEmptyPasswords", ("yes",),
     "SSH accepte les mots de passe vides",
     "la charte exige-t-elle un mot de passe non vide ?"),
]
RE_PARE_FEU = re.compile(r'(firewalld|ufw|iptables|nftables)')
RE_SSID = re.compile(r'^\s*ssid\s*=\s*(.+?)\s*$', re.M | re.I)
RE_ESSID = re.compile(r'^\s*ESSID\s*=\s*"?([^"\n]+)"?', re.M)
RE_NM_ID = re.compile(r'^\s*id\s*=\s*(.+?)\s*$', re.M)
RE_NM_UUID = re.compile(r'^\s*uuid\s*=\s*([0-9a-fA-F-]{36})', re.M)
RE_NM_PERM = re.compile(r'^\s*permissions\s*=\s*user:([^:;]+)', re.M)
RE_NM_DATE = re.compile(r'^([0-9a-fA-F-]{36})=(\d+)', re.M)


def reseau(c):
    """Rend la liste des réseaux sans fil enregistrés, en posant au passage
    les constats de durcissement.

    NetworkManager garde un fichier par connexion ; « timestamps » y ajoute la
    date de la dernière association. Un profil peut être réservé à un compte
    (« permissions=user:… ») : alors le constat lui revient, sinon il est du
    poste.
    """
    t = c.un("_reseau.tar.gz", "RESEAU")
    if not t:
        return []
    pare_feu, reseaux, dates = [], [], {}
    for nom, blob in c.membres_tar(t):
        txt = blob.decode("utf-8", "replace")
        base = os.path.basename(nom)
        if base == "sshd_config":
            for cle, mauvais, quoi, question in SSHD:
                for m in re.finditer(rf'^\s*{cle}\s+(\S+)', txt, re.M | re.I):
                    if m.group(1).lower() in mauvais:
                        constat("durcissement", quoi, f"{cle} {m.group(1)}",
                                f"{c.rel(t)} → {nom}",
                                f"grep {cle} dans sshd_config", question=question)
        if RE_PARE_FEU.search(nom):
            pare_feu.append(nom)
        if base == "ufw.conf":
            m = re.search(r'^\s*ENABLED\s*=\s*(\w+)', txt, re.M | re.I)
            if m and m.group(1).lower() != "yes":
                constat("durcissement", "pare-feu ufw désactivé", m.group(0).strip(),
                        f"{c.rel(t)} → {nom}", "grep ENABLED dans ufw.conf",
                        question="la charte impose-t-elle un pare-feu actif ?")
        if base == "timestamps" and "NetworkManager" in nom:
            for m in RE_NM_DATE.finditer(txt):
                dates[m.group(1).lower()] = int(m.group(2))
        elif "system-connections" in nom or "network-scripts" in nom:
            m = RE_SSID.search(txt)
            ssid = m.group(1) if m else None
            if ssid and re.fullmatch(r'(?:\d{1,3};)+', ssid):        # SSID non UTF-8
                ssid = bytes(int(x) for x in ssid.split(";") if x) \
                    .decode("utf-8", "replace")
            if not ssid:
                m = RE_ESSID.search(txt)
                ssid = m.group(1) if m else None
            idc, uuid, perm = RE_NM_ID.search(txt), RE_NM_UUID.search(txt), RE_NM_PERM.search(txt)
            reseaux.append({"ssid": ssid or (idc.group(1) if idc else
                                             os.path.splitext(base)[0]),
                            "id": idc.group(1) if idc else None,
                            "uuid": uuid.group(1).lower() if uuid else None,
                            "acteur": perm.group(1) if perm else None,
                            "source": f"{c.rel(t)} → {nom}"})
    if not pare_feu:
        constat("durcissement", "aucune configuration de pare-feu",
                "ni firewalld, ni ufw, ni iptables, ni nftables", c.rel(t),
                "recherche des chemins de pare-feu dans l'archive réseau",
                question="la charte impose-t-elle un pare-feu ?",
                note="absence de CONFIGURATION : un pare-feu peut avoir été "
                     "piloté autrement. À confirmer avant d'en faire un manquement.")
    for r in reseaux:
        q = dates.get(r["uuid"] or "")
        r["vu_le"] = _epoch_iso(q) if q else None
    return reseaux


# ── 3 · les dossiers des comptes, lus une seule fois ─────────────────
# Une archive de profil se compte en centaines de Mo. Elle est parcourue UNE
# fois, et chaque pièce utile en est tirée pour tous les contrôles à la fois :
# les bases de navigateur (balayées sur place, jamais gardées), les historiques
# d'interpréteur, les fichiers de secrets, les clés SSH.
#
# Les navigateurs vivent dans DEUX archives, et l'oublier fait manquer un
# navigateur entier : Firefox est dans ~/.mozilla, donc dans _profils ; Chrome
# installé par paquet est dans ~/.config/google-chrome, donc dans _artefacts.

BASES_NAVIGATEUR = ("places.sqlite", "History", "cookies.sqlite", "Cookies",
                    "Web Data", "Archived History")
FICHIERS_SECRETS = {
    ".netrc": "identifiants d'accès enregistrés en clair (.netrc)",
    ".git-credentials": "identifiants git enregistrés en clair",
    "credentials": "fichier d'identifiants (.aws/credentials ou équivalent)",
}
RE_HISTO_EPOCH = re.compile(r'^#(\d{9,11})$')
RE_HISTO_ZSH = re.compile(r'^: (\d{9,11}):\d+;(.*)$')
RE_INSTALLABLE = re.compile(r'\.(?:AppImage|deb|rpm|exe|msi)$', re.I)
RE_LS_PERMS = re.compile(r'^[-dlbcpsD][-rwxsStT]{9}')
RE_LS_ISO = re.compile(r'^\d{4}-\d{2}-\d{2}$')
RE_DATE_LOG = re.compile(r'^(\d{4}-\d{2}-\d{2}[ T|]\d{2}:\d{2}:\d{2})')


def _interesse(nom):
    base = os.path.basename(nom)
    return (base in BASES_NAVIGATEUR or base in FICHIERS_SECRETS
            or base.endswith(("_history", ".lesshst", ".pem", ".key"))
            or base.startswith("id_") or ".ssh/" in nom or ".gnupg/" in nom)


RE_HOTE = re.compile(
    rb'(?<![a-z0-9.-])(?:[a-z][a-z0-9+.-]{1,10}://)?(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}'
    rb'(?:[/?#][^\x00\s"\'<>]{0,120})?', re.I)


class Balayage:
    """Tous les motifs de domaine sur chaque base de navigateur, en un passage
    qui coûte peu.

    Appliquer vingt expressions à 50 Mo d'octets prend des minutes : le moteur
    essaie chaque alternative à chaque position. On ne le fait donc pas. Une
    seule expression simple extrait d'abord les NOMS D'HÔTE (avec leur schéma
    et le début du chemin) ; ils sont dédoublonnés et comptés — cent mille
    adresses uniques tiennent en quelques Mo — et les motifs ne courent que
    sur ce corpus-là. Les pages libérées de la base y sont : on lit les octets,
    pas les tables.
    """

    def __init__(self, motifs):
        self.motifs = [(ident, re.compile(brut)) for ident, brut in motifs]

    def compter(self, blob):
        """{identifiant: Counter(trouvé en minuscules → occurrences dans la base)}"""
        par = collections.defaultdict(collections.Counter)
        if not self.motifs:
            return par
        hotes = collections.Counter(m.group(0).lower().decode("latin-1")
                                    for m in RE_HOTE.finditer(blob))
        corpus = "\n".join(hotes)
        for ident, rx in self.motifs:
            for m in rx.finditer(corpus):
                d = corpus.rfind("\n", 0, m.start()) + 1
                f = corpus.find("\n", m.end())
                hote = corpus[d:f if f >= 0 else None]
                par[ident][m.group(0).lower()] += hotes[hote]
        return par


def lire_comptes(c, balayage):
    """Lit chaque archive de compte une fois. Rend un dict par compte :
    navigateurs [(source, comptes par motif)], historiques [(source, [(date, ligne)])],
    secrets [(source, nom)], cles [(source, nom, chiffree)]."""
    comptes_ = {}
    for suffixe in ("_profils.tar.gz", "_artefacts.tar.gz"):
        for arch in c.chercher(suffixe, "COMPTES"):
            compte = _compte_de(arch, suffixe[1:])
            p = comptes_.setdefault(compte, {"navigateurs": [], "historiques": [],
                                             "secrets": [], "cles": [], "autorisees": []})
            for nom, blob in c.membres_tar(arch, _interesse):
                base = os.path.basename(nom)
                source = f"{c.rel(arch)} → {nom}"
                if base in BASES_NAVIGATEUR:
                    # les octets, pas SQL : on lit aussi les pages libérées, et
                    # rien n'est jamais écrit dans la base, pas même un journal
                    p["navigateurs"].append((source, balayage.compter(blob)))
                elif base.endswith(("_history", ".lesshst")):
                    p["historiques"].append((source, _lignes_historique(blob)))
                elif base in FICHIERS_SECRETS:
                    if blob.strip():
                        p["secrets"].append((source, base))
                elif base == "authorized_keys":
                    for l in blob.decode("utf-8", "replace").splitlines():
                        ch = l.split()
                        if len(ch) >= 2 and not l.startswith("#"):
                            p["autorisees"].append((source, ch[1][:40], " ".join(ch[2:])[:60]))
                elif b"PRIVATE KEY" in blob:
                    chiffree = _cle_chiffree(blob)
                    if chiffree is not None:
                        p["cles"].append((source, nom, chiffree))
    return comptes_


def _lignes_historique(blob):
    """[(date, commande)] d'un historique d'interpréteur.

    bash ne date que si HISTTIMEFORMAT était posé : une ligne « #<epoch> »
    précède alors chaque commande. zsh, en mode étendu, écrit « : epoch:0;cmd ».
    Sans cela la date est None, et le constat doit le dire : la position d'une
    ligne dans le fichier ne prouve rien de son moment.
    """
    lignes, quand = [], None
    for l in blob.decode("utf-8", "replace").splitlines():
        m = RE_HISTO_EPOCH.match(l)
        if m:
            quand = _epoch_iso(int(m.group(1)))
            continue
        m = RE_HISTO_ZSH.match(l)
        if m:
            lignes.append((_epoch_iso(int(m.group(1))), m.group(2)))
            continue
        if l.strip():
            lignes.append((quand, l))
            quand = None
    return lignes


def _cle_chiffree(blob):
    """Une clé privée SSH est-elle protégée par une phrase de passe ?

    Deux formats. L'ancien (PEM) l'annonce en clair par « Proc-Type: ENCRYPTED ».
    Le nouveau (openssh-key-v1) nomme son algorithme juste après l'en-tête :
    « none » veut dire aucune protection.
    """
    txt = blob.decode("utf-8", "replace")
    if "Proc-Type:" in txt and "ENCRYPTED" in txt:
        return True
    if "BEGIN OPENSSH PRIVATE KEY" in txt:
        corps = "".join(l for l in txt.splitlines() if "-----" not in l)
        try:
            brut = base64.b64decode(corps + "===")
        except Exception:                                        # noqa: BLE001
            return None
        if not brut.startswith(b"openssh-key-v1\x00"):
            return None
        # après le magique : longueur (4 octets) puis le nom du chiffrement
        deb = len(b"openssh-key-v1\x00")
        taille = int.from_bytes(brut[deb:deb + 4], "big")
        return brut[deb + 4:deb + 4 + taille] != b"none"
    return "ENCRYPTED" in txt


def lire_inventaires(c):
    """Les chemins du dossier personnel.
    Rend {compte: (source, [(chemin, date ls, propriétaire)])}.

    L'inventaire est un « ls -lRa » : des en-têtes de dossier, puis des noms
    nus. Sans recoller les deux, un motif comme « .local/share/Steam/ » ne
    trouverait jamais rien. Le dossier du compte est remplacé par « ~ » : le
    point de montage de l'analyse n'a rien à faire dans un rapport. La date est
    celle que ls affiche, sans conversion : elle n'a pas d'année quand elle
    est récente, et sa langue est celle du poste d'analyse. Elle se cite.
    """
    inv = {}
    for f in c.chercher("_inventaire.txt", "COMPTES"):
        racine, courant, chemins = None, "", []
        for l in c.texte(f, 8_000_000).splitlines():
            # un en-tête de dossier finit par « : » et n'a pas la forme d'une
            # ligne de ls — un fichier peut très bien s'appeler « notes: »
            if l.endswith(":") and not RE_LS_PERMS.match(l):
                brut = l[:-1]
                if racine is None:
                    racine = brut
                courant = "~" + brut[len(racine):] if brut.startswith(racine) else brut
                continue
            ch = l.split(None, 8)
            if len(ch) < 8 or not RE_LS_PERMS.match(ch[0]):
                continue
            if RE_LS_ISO.match(ch[5]):                          # --time-style=long-iso
                nom, quand = " ".join(ch[7:]), " ".join(ch[5:7])
            else:                                               # « Jan  4 10:22 »
                nom, quand = (ch[8] if len(ch) > 8 else ""), " ".join(ch[5:8])
            nom = nom.split(" -> ", 1)[0]
            if nom and nom not in (".", ".."):
                chemins.append((f"{courant}/{nom}" if courant else nom, quand, ch[2]))
        inv[_compte_de(f, "inventaire.txt")] = (c.rel(f), chemins)
    return inv


def lire_paquets(c):
    """Ce qui est installé sur le POSTE. Rend [(source, methode, [(date, ligne)])].

    La liste des paquets ne dit pas qui les a posés : ces constats sont de
    portée « poste ». Les journaux d'installation, eux, portent une date —
    celle du poste, sans fuseau, telle que dpkg ou dnf l'écrivent.
    """
    out = []
    for f in c.chercher("_paquets.txt", "PAQUETS"):
        out.append((c.rel(f), "la liste des paquets installés",
                    [(None, l) for l in c.texte(f, 8_000_000).splitlines() if l.strip()]))
    for arch in c.chercher("_historique.tar.gz", "PAQUETS"):
        for nom, blob in c.membres_tar(arch):
            # history.sqlite de dnf est du binaire : ses journaux texte sont à côté
            if b"\x00" in blob[:4096]:
                continue
            lignes = []
            for l in blob.decode("utf-8", "replace").splitlines():
                if l.strip():
                    m = RE_DATE_LOG.match(l)
                    lignes.append((m.group(1).replace("|", " ") if m else None, l))
            if lignes:
                out.append((f"{c.rel(arch)} → {nom}",
                            "l'historique du gestionnaire de paquets", lignes))
    return out


# ── 4 · les contrôles fixes sur ces pièces ───────────────────────────
SECRETS = [
    (re.compile(r'(?:^|\s)(?:-p|--password[= ])\S+'), "mot de passe sur la ligne de commande"),
    (re.compile(r'\b(?:PASSWORD|PASSWD|PASS|TOKEN|SECRET|API_?KEY)\s*=\s*\S{6,}', re.I),
     "identifiant affecté en clair"),
    (re.compile(r'curl\s+[^|]*-u\s+\S+:\S+'), "identifiant passé à curl"),
    (re.compile(r'\bmysql\s+.*-p\S+'), "mot de passe mysql sur la ligne de commande"),
    (re.compile(r'sshpass\s+-p'), "mot de passe SSH passé en argument"),
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{12,})'),
     "jeton d'accès en clair"),
]

# Familles indicatives. La charte décide de ce qui est permis : ce tableau ne
# sert qu'à ranger les domaines pour la lecture, jamais à les condamner.
FAMILLES = [
    ("de stockage personnel en ligne",
     r'(?i)(wetransfer|transfernow|swisstransfer|dropbox|drive\.google|mega\.nz'
     r'|onedrive|1fichier|smash\.|grosfichiers|filesender)'),
    ("de messagerie personnelle",
     r'(?i)(mail\.google|outlook\.live|protonmail|proton\.me|yahoo.*mail|laposte\.net'
     r'|orange\.fr/webmail|free\.fr/webmail|gmx\.|zoho.*mail)'),
    ("d'intelligence artificielle générative",
     r'(?i)(chatgpt|openai\.com|claude\.ai|anthropic\.com|gemini\.google|mistral\.ai'
     r'|perplexity\.ai|copilot\.microsoft)'),
    ("de réseau social",
     r'(?i)(facebook|instagram|twitter|(?<![\w.])x\.com|linkedin|tiktok|snapchat|reddit)'),
    ("de dépôt de code public",
     r'(?i)(github\.com|gitlab\.com|bitbucket|pastebin|gist\.github)'),
    ("d'accès distant grand public",
     r'(?i)(teamviewer|anydesk|logmein|ngrok|localtunnel)'),
]


def secrets(comptes_):
    for compte, p in sorted(comptes_.items()):
        for source, base in p["secrets"]:
            constat("secrets", FICHIERS_SECRETS[base], source.split(" → ")[-1],
                    source, "présence du fichier", acteur=compte,
                    question="la charte interdit-elle d'enregistrer des "
                             "identifiants en clair ?")
        for source, nom, chiffree in p["cles"]:
            if chiffree:
                constat("secrets", "clé privée SSH protégée par une phrase de passe",
                        nom, source, "en-tête de la clé", acteur=compte,
                        note="conforme à l'usage recommandé")
            else:
                constat("secrets", "clé privée SSH SANS phrase de passe", nom, source,
                        "lecture de l'en-tête de la clé : chiffrement « none »",
                        acteur=compte,
                        question="la charte impose-t-elle une phrase de passe sur "
                                 "les clés privées ?",
                        note="quiconque obtient ce fichier peut se connecter "
                             "partout où la clé est acceptée")
        for source, lignes in p["historiques"]:
            for date, l in lignes:
                for motif, quoi in SECRETS:
                    if motif.search(l):
                        constat("secrets", quoi, l.strip()[:140], source,
                                f"motif « {motif.pattern[:40]} » dans l'historique",
                                acteur=compte, date=date,
                                question="la charte interdit-elle de saisir un "
                                         "secret en argument de commande ?",
                                note=None if date else
                                     "l'historique n'est pas daté : ne datez pas "
                                     "cette ligne sans autre source")
                        break


def usage(c, comptes_, inventaires):
    """Ce qui a servi. Rien n'est qualifié : les familles rangent, la charte juge."""
    for compte, p in sorted(comptes_.items()):
        vus = set()
        for source, comptages in p["navigateurs"]:
            for famille, _ in FAMILLES:
                for v in sorted(comptages.get(famille, ())):
                    if (famille, v) in vus:
                        continue
                    vus.add((famille, v))
                    constat("usage", f"service {famille} présent dans un "
                            "profil de navigateur", v, source,
                            "recherche de motifs de domaines dans la base du "
                            "navigateur (sans l'ouvrir en SQL)", acteur=compte,
                            question=f"la charte encadre-t-elle l'usage d'un "
                                     f"service {famille} sur un poste "
                                     f"professionnel ?",
                            note="présence dans la base : la date exacte se lit "
                                 "dans faits.jsonl du skill forensic-linux")

    # Supports amovibles : le journal les porte, avec le compte dans le chemin.
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        for compte, etiquette in sorted(set(re.findall(r'/run/media/([^/\s]+)/(\S+)',
                                                       c.texte(j)))):
            constat("usage", "support amovible monté", etiquette,
                    c.rel(j), "chemins /run/media/<compte>/ dans le journal",
                    acteur=compte,
                    question="la charte encadre-t-elle l'usage de supports "
                             "amovibles, et exige-t-elle qu'ils soient chiffrés ?")

    for compte, (source, chemins) in sorted(inventaires.items()):
        for chemin, quand, _ in chemins:
            if RE_INSTALLABLE.search(chemin):
                constat("usage", "programme installable présent dans un dossier "
                        "personnel", chemin, source, "recherche d'extensions dans "
                        "l'inventaire du profil", acteur=compte,
                        note=f"date affichée par ls : {quand}" if quand else None,
                        question="la charte réserve-t-elle l'installation de "
                                 "logiciels au service informatique ?")


# ── 4 bis · un compte servi par un autre ─────────────────────────────
# Un compte est une identité numérique ; qu'une autre personne s'en serve
# efface l'attribution de tout le reste. Aucune pièce ne le prouve seule, mais
# quatre traces le font soupçonner, et chacune se cite avec sa limite.
RE_PRISE_IDENTITE = re.compile(
    r'(?:^|[;&|]\s*)(?:sudo\s+(?:-\S+\s+)*-u\s+(\S+)|su\s+(?:-\s+|-l\s+|--login\s+)?(\S+)|ssh\s+(?:-\S+\s+)*(\S+)@\S+)')


def partage(c, comptes_, inventaires, faits, locaux):
    for compte, (source, chemins) in sorted(inventaires.items()):
        autres = collections.defaultdict(list)
        for chemin, quand, prop in chemins:
            if prop and prop not in (compte, "root"):
                autres[prop].append(_avec_date(chemin, quand))
        for prop, ex in sorted(autres.items()):
            constat("partage", "fichiers appartenant à un autre compte dans le "
                    "dossier personnel", f"{prop} : {len(ex)} fichier(s)", source,
                    "colonne propriétaire de ls -lRa, comparée au compte du dossier",
                    acteur=compte,
                    question="la charte interdit-elle l'usage du compte d'autrui, ou "
                             "le partage d'un poste de travail ?",
                    note="par exemple : " + " ; ".join(ex[:5]) + ". Un fichier créé "
                         "par un autre compte dans ce dossier suppose que ce compte "
                         "y a écrit — par une session à lui, ou par sudo")
    for compte, p in sorted(comptes_.items()):
        for source, lignes in p["historiques"]:
            for v, (n, ex, dates) in sorted(_grouper([(l, d) for d, l in lignes],
                                                     RE_PRISE_IDENTITE).items()):
                cible = next((g for g in RE_PRISE_IDENTITE.search(v).groups() if g), "")
                if cible.startswith("-") or cible not in locaux or cible == compte:
                    continue
                constat("partage", "prise de l'identité d'un autre compte local "
                        "depuis l'interpréteur", f"{compte} → {cible}", source,
                        f"motif su / sudo -u / ssh compte@ dans l'historique",
                        acteur=compte, date=dates[-1] if dates else None,
                        question="la charte interdit-elle d'agir sous le compte "
                                 "d'un autre ?",
                        note=f"{n} saisie(s), par exemple : " + " ; ".join(x.strip()[:80] for x in ex)
                             + (". Historique non daté" if not dates else ""))
    # la même clé publique acceptée par deux comptes : une seule clé privée
    # ouvre les deux
    par_cle = collections.defaultdict(list)
    for compte, p in comptes_.items():
        for source, cle, commentaire in p["autorisees"]:
            par_cle[cle].append((compte, source, commentaire))
    for cle, ou in sorted(par_cle.items()):
        comptes_vus = sorted({x[0] for x in ou})
        if len(comptes_vus) > 1:
            constat("partage", "la même clé SSH ouvre plusieurs comptes",
                    ", ".join(comptes_vus), " ; ".join(sorted({x[1] for x in ou})),
                    "comparaison des clés de .ssh/authorized_keys entre comptes",
                    question="la charte impose-t-elle une clé par personne et par "
                             "compte ?",
                    note=f"clé {cle}… ({ou[0][2] or 'sans commentaire'}) : qui détient "
                         "la clé privée agit sous tous ces comptes")
    # deux ouvertures du même compte depuis deux origines à moins de dix
    # minutes : deux personnes, ou une seule et deux machines — à vérifier
    ouvertures = collections.defaultdict(list)
    for f in faits:
        if f.get("categorie") == "evenement" and "ouverture de session" in f.get("fait", "") \
                and f.get("acteur") and f.get("horodatage"):
            m = re.search(r'depuis (\S+)', f.get("note") or "")
            try:
                q = datetime.fromisoformat(f["horodatage"].replace("Z", "+00:00"))
            except ValueError:
                continue
            ouvertures[f["acteur"]].append((q, m.group(1) if m else "console", f["id"]))
        if f.get("categorie") == "evenement" and f.get("fait") == "changement d'utilisateur (su)":
            cible = re.search(r'est devenu (\S+)', f.get("note") or "")
            if cible and cible.group(1) in locaux and cible.group(1) != f.get("acteur"):
                constat("partage", "prise de l'identité d'un autre compte local (su)",
                        f"{f.get('acteur')} → {cible.group(1)}",
                        "faits.jsonl (skill forensic-linux)",
                        f"fait {f['id']} : ligne « session opened for user » du journal",
                        acteur=f.get("acteur"), date=f["horodatage"],
                        question="la charte interdit-elle d'agir sous le compte d'un autre ?")
    for compte, liste in sorted(ouvertures.items()):
        liste.sort()
        for (q1, o1, i1), (q2, o2, i2) in zip(liste, liste[1:]):
            if o1 != o2 and (q2 - q1).total_seconds() < 600:
                constat("partage", "deux ouvertures du même compte depuis deux "
                        "origines à moins de dix minutes",
                        f"{o1} puis {o2}", "faits.jsonl (skill forensic-linux)",
                        f"faits {i1} et {i2}, horodatages comparés", acteur=compte,
                        date=q2.isoformat().replace("+00:00", "Z"),
                        question="la charte interdit-elle de prêter son compte ?",
                        note="deux personnes, ou une seule avec deux machines : la "
                             "collecte ne tranche pas. Croiser avec les adresses "
                             "attribuées à chaque poste")


# ── 5 · les règles fournies ──────────────────────────────────────────
# Une règle de la charte n'est pas un contrôle : c'est une phrase. La traduire
# en quelque chose que l'on cherche dans une collecte est une INTERPRÉTATION, et
# un lecteur doit pouvoir la contester. D'où ce fichier de règles, écrit à la
# main, lisible par qui n'écrit pas de Python : la traduction y est visible, et
# elle se corrige sans toucher au code.
#
# Le format est décrit dans references/regles/usage-non-professionnel.regles.

CLES_REGLE = ("regle", "titre", "texte", "portee", "theme")
CLES_INDICE = ("domaine", "programme", "fichier", "commande", "wifi", "horaire",
               "chaine", "controle")

# Ce qu'un indice établit — et pas davantage. Chaque constat l'emporte avec lui
# pour que le rapport ne puisse pas, par distraction, en dire plus.
PREUVE = {
    "domaine": "une CONSULTATION du site à la date que porte l'historique — "
               "ni un téléchargement, ni un envoi de données",
    "programme": "la PRÉSENCE du programme, pas son exécution ni l'usage qui "
                 "en a été fait",
    "fichier": "la PRÉSENCE d'un fichier dans le dossier du compte, pas qui "
               "l'y a mis ni ce qu'il contient",
    "commande": "qu'une commande a été SAISIE dans l'interpréteur de ce compte "
                "— datée seulement si l'historique l'est",
    "wifi": "que la machine s'est ASSOCIÉE au moins une fois à ce réseau — "
            "donc qu'elle est sortie du site",
    "horaire": "qu'une session a été OUVERTE hors des heures indiquées, pas "
               "qu'un travail y a été fait",
    "chaine": "que la chaîne FIGURE dans la pièce citée — pas ce qu'elle y faisait",
    "controle": "ce que le contrôle fixe établit, écrit dans son propre constat",
}
# Ce qu'il faut avoir lu pour chercher chaque indice, et ce qu'on dit sinon.
PIECE_REQUISE = {
    "domaine": (("navigateurs",), "aucune base de navigateur dans la collecte"),
    "programme": (("paquets", "inventaires"), "ni liste de paquets ni inventaire"),
    "fichier": (("inventaires",), "aucun inventaire de dossier personnel"),
    "commande": (("historiques",), "aucun historique d'interpréteur"),
    "wifi": (("reseaux",), "aucun profil de connexion réseau"),
    "horaire": (("faits",), "les heures demandent --faits (faits.jsonl du skill "
                            "forensic-linux)"),
    "chaine": (("textes",), "aucune pièce texte dans la collecte"),
    "controle": (("comptes", "inventaires", "paquets", "reseaux"), "aucune pièce"),
}


class Absente(Exception):
    """Un chercheur découvre en route qu'il lui manque la pièce."""

JOURS = ("lun", "mar", "mer", "jeu", "ven", "sam", "dim")
RE_PLAGE = re.compile(
    r'^(%s)\s*-\s*(%s)\s+(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$'
    % ("|".join(JOURS), "|".join(JOURS)), re.I)


def lire_regles(chemin):
    """Lit un fichier .regles. Un bloc par règle, séparés par une ligne vide.

    Toute erreur est fatale et nommée avec son numéro de ligne : mieux vaut
    refuser de tourner qu'analyser avec une règle silencieusement ignorée.
    """
    regles, bloc, debut = [], {}, 0

    def clore():
        if not bloc:
            return
        if not bloc.get("regle"):
            sys.exit(f"{chemin}:{debut} : bloc sans « regle: »")
        if not bloc.get("texte"):
            sys.exit(f"{chemin}:{debut} : la règle {bloc['regle']} n'a pas de "
                     "« texte: » — recopiez la phrase de la charte, c'est elle "
                     "qui fait foi")
        bloc.setdefault("titre", bloc["regle"])
        bloc.setdefault("portee", "compte")
        bloc.setdefault("theme", "usage")
        bloc.setdefault("indices", [])
        regles.append(dict(bloc))
        bloc.clear()

    with open(chemin, encoding="utf-8") as fh:
        for num, ligne in enumerate(fh, 1):
            nue = ligne.strip()
            if not nue:
                clore()
                continue
            if nue.startswith("#"):
                continue
            if ":" not in nue:
                sys.exit(f"{chemin}:{num} : ligne sans « clé: valeur » — {nue}")
            cle, valeur = nue.split(":", 1)
            cle, valeur = cle.strip().lower(), valeur.strip()
            if cle in CLES_INDICE:
                # « motif   # étiquette » : le commentaire de fin de ligne sert
                # d'étiquette. Il faut un blanc devant le # — un motif peut en
                # contenir un.
                etiquette = None
                coupe = re.search(r'\s+#\s*(.*)$', valeur)
                if coupe:
                    etiquette = coupe.group(1).strip() or None
                    valeur = valeur[:coupe.start()].strip()
                if not bloc:
                    sys.exit(f"{chemin}:{num} : indice « {cle} » hors d'un bloc")
                if cle == "controle":
                    motif = valeur.strip().lower()
                elif cle == "horaire":
                    m = RE_PLAGE.match(valeur)
                    if not m:
                        sys.exit(f"{chemin}:{num} : horaire illisible — attendu "
                                 "« lun-ven 08:00-19:00 »")
                    d, f = JOURS.index(m.group(1).lower()), JOURS.index(m.group(2).lower())
                    motif = ({j % 7 for j in range(d, f + 1 if f >= d else f + 8)},
                             int(m.group(3)) * 60 + int(m.group(4)),
                             int(m.group(5)) * 60 + int(m.group(6)))
                else:
                    try:
                        motif = re.compile(valeur)
                    except re.error as e:
                        sys.exit(f"{chemin}:{num} : motif illisible ({e}) — {valeur}")
                bloc.setdefault("indices", []).append((cle, motif, etiquette, valeur))
            elif cle in CLES_REGLE:
                if not bloc:
                    debut = num
                bloc[cle] = valeur
            else:
                sys.exit(f"{chemin}:{num} : clé « {cle} » inconnue — attendu "
                         + ", ".join(CLES_REGLE + CLES_INDICE))
    clore()
    if not regles:
        sys.exit(f"{chemin} : aucune règle lisible")
    return regles


def lire_faits(chemin):
    faits = []
    with open(chemin, encoding="utf-8") as fh:
        for ligne in fh:
            ligne = ligne.strip()
            if ligne:
                try:
                    faits.append(json.loads(ligne))
                except json.JSONDecodeError:
                    pass
    return faits


def _grouper(lignes, motif):
    """Groupe les trouvailles d'un motif sur des (texte, date) :
    {trouvé en minuscules: (n, [exemples ≤ 5], [dates triées])}.

    Un dossier de films donne mille lignes pour un seul indice. Grouper rend le
    constat lisible et borné, sans perdre le compte, les exemples ni les dates.
    """
    par = {}
    for texte, date in lignes:
        for m in motif.finditer(texte):
            g = par.setdefault(m.group(0).lower(), [0, [], []])
            g[0] += 1
            if len(g[1]) < 5 and texte not in g[1]:
                g[1].append(texte)
            if date:
                g[2].append(date)
    for g in par.values():
        g[2].sort()
    return par


def _avec_date(texte, date):
    return f"{texte} ({date})" if date else texte


# Les chercheurs : un par type d'indice. Chacun rend des dicts prêts pour
# _poser — quoi, valeur, source, methode, et acteur/portee/date/note.
def _chercher_domaine(pieces, motif, brut, ident, faits):
    visites = pieces.get("visites") or {}
    for compte, p in sorted(pieces["comptes"].items()):
        for source, comptages in p["navigateurs"]:
            for v, n in sorted(comptages.get(ident, {}).items()):
                date, note = None, f"{n} occurrence(s) dans la base"
                # les faits du skill forensic datent la visite — et
                # distinguent une visite d'un téléchargement
                liees = [f for f in visites.get(compte, ()) if v in f["_texte"]]
                if liees:
                    dates = sorted(f["horodatage"] for f in liees)
                    date = dates[-1]
                    note += (f" ; {len(liees)} fait(s) daté(s) dans faits.jsonl, "
                             f"du {dates[0]} au {dates[-1]} : "
                             + ", ".join(f["id"] for f in liees[:8]))
                    charges = [f["id"] for f in liees if f["categorie"] == "telechargement"]
                    if charges:
                        note += (" — dont un TÉLÉCHARGEMENT (" + ", ".join(charges[:4])
                                 + ") : plus qu'une consultation, à citer comme tel")
                elif faits:
                    note += (" ; aucun fait daté ne cite ce domaine : il vient des "
                             "cookies, d'un favori ou d'une page libérée — pas "
                             "d'une visite datée")
                else:
                    note += " ; la date se lit avec --faits"
                yield dict(quoi="domaine présent dans une base de navigateur",
                           valeur=v, source=source, acteur=compte, date=date,
                           methode=f"motif « {brut} » cherché dans les octets de "
                                   "la base, sans l'ouvrir en SQL", note=note)


def _chercher_inventaire(pieces, motif, brut, quoi):
    for compte, (source, chemins) in sorted(pieces["inventaires"].items()):
        par_chemin = {ch: q for ch, q, _ in chemins}
        for v, (n, ex, dates) in sorted(_grouper([(ch, None) for ch, _, _ in chemins],
                                                  motif).items()):
            yield dict(quoi=quoi, valeur=v, source=source, acteur=compte,
                       methode=f"motif « {brut} » cherché dans les chemins de "
                               "l'inventaire (ls -lRa)",
                       note=f"{n} chemin(s), par exemple : "
                            + " ; ".join(_avec_date(x, par_chemin.get(x)) for x in ex)
                            + ". La date entre parenthèses est celle que ls "
                            "affiche : modification, sans année si récente")


def _chercher_programme(pieces, motif, brut, ident, faits):
    for source, methode, lignes in pieces["paquets"]:
        for v, (n, ex, dates) in sorted(_grouper([(l, d) for d, l in lignes], motif).items()):
            yield dict(quoi="programme installé sur le poste", valeur=v, source=source,
                       portee="poste", date=dates[-1] if dates else None,
                       methode=f"motif « {brut} » cherché dans {methode}",
                       note="la liste des paquets ne dit pas quel compte a demandé "
                            "l'installation : la portée est le poste. Ligne : "
                            + ex[0].strip()[:120])
    yield from _chercher_inventaire(pieces, motif, brut,
                                    "programme présent dans le dossier personnel")


def _chercher_fichier(pieces, motif, brut, ident, faits):
    yield from _chercher_inventaire(pieces, motif, brut,
                                    "fichier présent dans le dossier personnel")


def _chercher_commande(pieces, motif, brut, ident, faits):
    for compte, p in sorted(pieces["comptes"].items()):
        for source, lignes in p["historiques"]:
            for v, (n, ex, dates) in sorted(_grouper([(l, d) for d, l in lignes], motif).items()):
                if dates:
                    note = (f"{n} saisie(s), {len(dates)} datée(s) du {dates[0]} au "
                            f"{dates[-1]} (HISTTIMEFORMAT posé)")
                else:
                    note = (f"{n} saisie(s), AUCUNE datée : l'historique n'a pas de "
                            "dates, ne lui en donnez pas")
                yield dict(quoi="commande saisie dans l'interpréteur", valeur=v,
                           source=source, acteur=compte,
                           date=dates[-1] if dates else None,
                           methode=f"motif « {brut} » cherché ligne à ligne dans "
                                   "l'historique de l'interpréteur",
                           note=note + ". Par exemple : "
                                + " ; ".join(x.strip()[:100] for x in ex))


def _chercher_wifi(pieces, motif, brut, ident, faits):
    for o in pieces["reseaux"]:
        if not motif.search(" ".join(x for x in (o["ssid"], o["id"]) if x)):
            continue
        yield dict(quoi="réseau sans fil enregistré sur le poste", valeur=o["ssid"],
                   source=o["source"], acteur=o["acteur"], date=o["vu_le"],
                   portee="compte" if o["acteur"] else "poste",
                   methode=f"motif « {brut} » cherché dans le SSID des profils "
                           "NetworkManager",
                   note="date de la dernière association, lue dans "
                        "var/lib/NetworkManager/timestamps" if o["vu_le"] else
                        "aucune date : le fichier « timestamps » de NetworkManager "
                        "manque ou ne connaît pas ce profil")


def _chercher_horaire(pieces, motif, brut, ident, faits):
    """Les ouvertures de session hors des heures ouvrées, groupées par journée.

    C'est le seul endroit où le fuseau compte AVANT le rapport : dire qu'une
    session est « hors heures » suppose de lire l'heure dans le fuseau du poste.
    """
    jours, deb, fin = motif
    fuseau = pieces["fuseau"]
    par, lus = {}, 0
    for f in faits:
        if f.get("categorie") != "evenement" or not f.get("horodatage") or \
                "ouverture de session" not in f.get("fait", ""):
            continue
        try:
            q = datetime.fromisoformat(f["horodatage"].replace("Z", "+00:00"))
        except ValueError:
            continue
        lus += 1
        if q.tzinfo and fuseau:
            q = q.astimezone(fuseau)
        if q.weekday() in jours and deb <= q.hour * 60 + q.minute < fin:
            continue
        cle_j = (f.get("acteur") or "?", q.date().isoformat())
        par.setdefault(cle_j, []).append((q.strftime("%H:%M"), f.get("id", "")))
    if not lus:
        raise Absente("aucune ouverture de session datée dans faits.jsonl")
    nom_fuseau = str(fuseau) if fuseau else "celui que portent les faits"
    for (qui, jour), heures in sorted(par.items()):
        heures.sort()
        yield dict(quoi="session ouverte hors des heures indiquées",
                   valeur=f"{jour} ({JOURS[datetime.fromisoformat(jour).weekday()]}) : "
                          + ", ".join(h for h, _ in heures),
                   source="faits.jsonl (skill forensic-linux)",
                   acteur=None if qui == "?" else qui, date=jour,
                   methode=f"heures ouvrées « {brut} » comparées à l'horodatage des "
                           f"ouvertures de session, lues dans le fuseau {nom_fuseau}",
                   note=f"{len(heures)} ouverture(s) : "
                        + ", ".join(i for _, i in heures if i))


def _chercher_texte(pieces, motif, brut, ident, faits):
    """Une chaîne ou une expression, dans toutes les pièces texte : historiques
    et inventaires des comptes, paquets, journal du poste."""
    for source, acteur, lignes in pieces["textes"]:
        for v, (n, ex, dates) in sorted(_grouper(lignes, motif).items()):
            yield dict(quoi="texte présent dans une pièce", valeur=v, source=source,
                       acteur=acteur, date=dates[-1] if dates else None,
                       portee="compte" if acteur else "poste",
                       methode=f"motif « {brut} » cherché ligne à ligne",
                       note=f"{n} ligne(s), par exemple : "
                            + " ; ".join(x.strip()[:100] for x in ex))


CHERCHEURS = {"domaine": _chercher_domaine, "programme": _chercher_programme,
              "fichier": _chercher_fichier, "commande": _chercher_commande,
              "wifi": _chercher_wifi, "horaire": _chercher_horaire,
              "chaine": _chercher_texte}


def appliquer_regles(c, regles, pieces, faits):
    """Cherche dans la collecte les indices que les règles désignent.

    Deux silences qui ne se confondent pas : la pièce manquait — « limite »,
    la règle n'a pas été vérifiée — ou elle était là et n'a rien donné —
    « conforme », en disant que cela ne prouve pas le respect de la règle.
    """
    for r in regles:
        poses, absentes, deja = 0, [], set()
        for cle, motif, etiquette, brut in r["indices"]:
            if cle == "controle":
                # la règle s'adosse à un contrôle fixe : ses constats déjà posés
                # — thème, ou thème/début du libellé — reçoivent le numéro
                theme, _, debut = motif.partition("/")
                for x in CONSTATS:
                    if x["theme"] == theme and x["constat"].lower().startswith(debut) \
                            and not x.get("regle"):
                        x["regle"] = r["regle"]
                        x["question"] = (f"règle {r['regle']} « {r['titre']} » — ce "
                                         "contrôle traduit-il fidèlement ce que dit la règle ?")
                        poses += 1
                continue
            requises, manque = PIECE_REQUISE[cle]
            if not any(pieces.get(p) for p in requises):
                absentes.append(manque)
                continue
            try:
                trouves = list(CHERCHEURS[cle](pieces, motif, brut, (r["regle"], brut), faits))
            except Absente as e:
                absentes.append(str(e))
                continue
            for t in trouves:
                # Deux motifs d'une même règle attrapent souvent la même chose —
                # « mcdo » et « mcdonalds.?free » sur le même réseau. Une pièce,
                # un constat.
                empreinte_c = (cle, t["source"], str(t["valeur"]).lower(), t.get("acteur"))
                if empreinte_c in deja:
                    continue
                deja.add(empreinte_c)
                poses += 1
                note = f"ce que cet indice établit : {PREUVE[cle]}"
                if etiquette:
                    note = f"catégorie donnée par la règle : {etiquette}. " + note
                if t.get("note"):
                    note = t["note"] + ". " + note
                constat(r["theme"], t["quoi"], t["valeur"], t["source"], t["methode"],
                        regle=r["regle"], acteur=t.get("acteur"), date=t.get("date"),
                        portee=t.get("portee") or (r["portee"] if t.get("acteur") else "poste"),
                        question=f"règle {r['regle']} « {r['titre']} » — l'indice "
                                 f"« {brut} » traduit-il fidèlement ce que dit la règle ?",
                        note=note)
        for quoi in dict.fromkeys(absentes):
            constat("limite", f"règle {r['regle']} : {quoi}", r["titre"], c.prefix,
                    "recherche des indices de la règle dans la collecte",
                    regle=r["regle"],
                    note="un indice de cette règle n'a pas pu être cherché ; "
                         "l'absence de la pièce n'est pas l'absence de manquement. "
                         "Voir references/ou-chercher.md du skill forensic-linux "
                         "pour la reprendre")
        if not poses and not absentes:
            constat("conforme", f"règle {r['regle']} : aucun indice trouvé",
                    r["titre"], c.prefix,
                    f"recherche, dans les pièces disponibles, des {len(r['indices'])} "
                    "indices de la règle", regle=r["regle"],
                    note="aucun indice ne prouve pas le respect de la règle : les "
                         "indices sont ceux qu'on a su écrire, et un historique "
                         "s'efface")


def _pieces_texte(c, comptes_, inventaires, paquets):
    """[(source, acteur, [(ligne, date)])] : tout ce qui se lit ligne à ligne."""
    textes = []
    for compte, p in sorted(comptes_.items()):
        for source, lignes in p["historiques"]:
            textes.append((source, compte, [(l, d) for d, l in lignes]))
    for compte, (source, chemins) in sorted(inventaires.items()):
        textes.append((source, compte, [(ch, None) for ch, _, _ in chemins]))
    for source, _, lignes in paquets:
        textes.append((source, None, [(l, d) for d, l in lignes]))
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        textes.append((c.rel(j), None, [(l, None) for l in c.texte(j, 200_000_000).splitlines()]))
    return textes


def _visites_par_compte(faits):
    """Les faits de navigation datés, par compte, avec leur texte en minuscules
    prêt pour la recherche : de quoi dater un domaine."""
    par = {}
    for f in faits:
        if f.get("categorie") in ("navigation", "telechargement") and \
                f.get("horodatage") and f.get("acteur"):
            f["_texte"] = (f["valeur"] + " " + (f.get("note") or "")).lower()
            par.setdefault(f["acteur"], []).append(f)
    return par


def _fuseau(demande, faits):
    """Dans quel fuseau lire les heures : ce que l'analyste impose, puis ce que
    le poste déclarait (/etc/localtime, relevé par le skill forensic-linux),
    puis rien — et la méthode du constat le dira."""
    nom = demande
    if not nom:
        for f in faits:
            if f.get("fait") == "fuseau horaire du poste" and f.get("valeur"):
                nom = f["valeur"].strip()
                break
    if not nom:
        return None
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(nom)
    except Exception as e:                                        # noqa: BLE001
        print(f"  ! fuseau « {nom} » inutilisable ({e}) : les heures seront "
              "lues telles quelles", file=sys.stderr)
        return None


# ── mise en ordre ────────────────────────────────────────────────────
def empreinte(chemin):
    h = hashlib.sha256()
    with open(chemin, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def _csv_sain(v):
    """Une cellule qu'un tableur affichera, sans jamais l'exécuter.

    Une valeur venue d'une collecte est hostile par principe : un nom de
    fichier « =HYPERLINK(...) » ou « -2+3|cmd » devient une formule dans Excel
    ou LibreOffice. Un guillemet simple devant neutralise l'interprétation ;
    les retours à la ligne deviennent des espaces, pour que la ligne reste une
    ligne.
    """
    if v is None:
        return ""
    t = str(v).replace("\r", " ").replace("\n", " ")
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "|") else t


def ecrire_csv(chemin, lignes, colonnes):
    """Le même contenu que le .jsonl, pour un tableur : « ; » et BOM, ce
    qu'Excel et LibreOffice ouvrent sans dialogue en français."""
    with open(chemin, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";", quoting=csv.QUOTE_ALL)
        w.writerow(colonnes)
        for x in lignes:
            w.writerow([_csv_sain(x.get(k)) for k in colonnes])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("collecte")
    ap.add_argument("-o", "--sortie", default="constats.jsonl")
    ap.add_argument("--regles", metavar="FICHIER.regles",
                    help="règles écrites à la main à chercher dans la collecte")
    ap.add_argument("--faits", metavar="faits.jsonl",
                    help="les faits du skill forensic-linux : ils portent les "
                         "dates, nécessaires aux règles d'horaires")
    ap.add_argument("--fuseau", metavar="Europe/Paris",
                    help="fuseau dans lequel lire les heures ; par défaut celui "
                         "que faits.jsonl a relevé sur le poste")
    args = ap.parse_args()

    c = Collecte(args.collecte)
    regles = lire_regles(args.regles) if args.regles else []
    faits = lire_faits(args.faits) if args.faits else []

    # tous les motifs de domaine — familles fixes et règles — en un balayage
    motifs = [(f, m) for f, m in FAMILLES]
    for r in regles:
        motifs += [((r["regle"], brut), brut) for cle, _, _, brut in r["indices"]
                   if cle == "domaine"]
    balayage = Balayage(motifs)

    etapes = [("lecture des comptes", lambda: lire_comptes(c, balayage)),
              ("inventaires", lambda: lire_inventaires(c)),
              ("paquets", lambda: lire_paquets(c)),
              ("réseau et durcissement", lambda: reseau(c))]
    pieces = {"faits": faits, "fuseau": _fuseau(args.fuseau, faits),
              "visites": _visites_par_compte(faits)}
    for (nom, fn), cle in zip(etapes, ("comptes", "inventaires", "paquets", "reseaux")):
        avant = len(CONSTATS)
        try:
            pieces[cle] = fn()
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! {nom} : {type(e).__name__} {e}", file=sys.stderr)
            pieces[cle] = {} if cle in ("comptes", "inventaires") else []
        print(f"  {nom:26s} {len(CONSTATS) - avant:4d} constats", file=sys.stderr)
    comptes_ = pieces["comptes"]
    pieces["navigateurs"] = any(p["navigateurs"] for p in comptes_.values())
    pieces["historiques"] = any(p["historiques"] for p in comptes_.values())
    if any(cle == "chaine" for r in regles for cle, _, _, _ in r["indices"]):
        pieces["textes"] = _pieces_texte(c, comptes_, pieces["inventaires"], pieces["paquets"])
    locaux = set()
    p = c.un("passwd", "COMPTES")
    if p:
        locaux = {l.split(":")[0] for l in c.texte(p).splitlines() if ":" in l}

    for nom, fn in (("comptes et mots de passe", lambda: comptes(c)),
                    ("secrets", lambda: secrets(comptes_)),
                    ("usage", lambda: usage(c, comptes_, pieces["inventaires"])),
                    ("partage de compte",
                     lambda: partage(c, comptes_, pieces["inventaires"], faits, locaux))):
        avant = len(CONSTATS)
        try:
            fn()
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! {nom} : {type(e).__name__} {e}", file=sys.stderr)
        print(f"  {nom:26s} {len(CONSTATS) - avant:4d} constats", file=sys.stderr)
    if regles:
        avant = len(CONSTATS)
        appliquer_regles(c, regles, pieces, faits)
        print(f"  {'règles fournies':26s} {len(CONSTATS) - avant:4d} constats "
              f"({len(regles)} règles)", file=sys.stderr)

    with open(args.sortie, "w", encoding="utf-8") as fh:
        for x in CONSTATS:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    base = os.path.splitext(args.sortie)[0]
    ecrire_csv(base + ".csv", CONSTATS, COLONNES_CSV)

    man = base + "-manifeste.json"
    with open(man, "w", encoding="utf-8") as fh:
        json.dump({"collecte": c.prefix, "chemin_analyse": c.racine,
                   "outil": {"fichier": os.path.basename(os.path.abspath(__file__)),
                             "sha256": empreinte(os.path.abspath(__file__))},
                   "commande": " ".join(sys.argv),
                   "releve_le": datetime.now().astimezone().isoformat(),
                   "constats": len(CONSTATS),
                   "regles": ({"fichier": os.path.abspath(args.regles),
                               "sha256": empreinte(args.regles),
                               "liste": [{"regle": r["regle"], "titre": r["titre"],
                                          "texte": r["texte"], "portee": r["portee"],
                                          "indices": [{"type": k, "motif": b,
                                                       "etiquette": e}
                                                      for k, _, e, b in r["indices"]]}
                                         for r in regles]}
                              if args.regles else None),
                   "faits": os.path.abspath(args.faits) if args.faits else None,
                   "constats_sha256": empreinte(args.sortie),
                   "csv_sha256": empreinte(base + ".csv"),
                   "pieces_lues": {c.rel(p): {"sha256": empreinte(p),
                                              "octets": os.path.getsize(p)}
                                   for p in sorted(c.lus) if os.path.isfile(p)}},
                  fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    par = collections.Counter(x["theme"] for x in CONSTATS)
    print(f"\n{len(CONSTATS)} constats → {args.sortie}  (+ {base}.csv)", file=sys.stderr)
    print(f"  empreintes → {man}", file=sys.stderr)
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(par.items())), file=sys.stderr)
    if regles:
        par_regle = collections.Counter(
            x["regle"] for x in CONSTATS if x.get("regle") and x["theme"] not in SANS_REGLE)
        limites = {x["regle"] for x in CONSTATS if x.get("regle") and x["theme"] == "limite"}
        print("", file=sys.stderr)
        for r in regles:
            n = par_regle.get(r["regle"], 0)
            etat = f"{n} constats" if n else "aucun indice"
            if r["regle"] in limites:
                etat += " — indices non cherchés, pièce absente"
            print(f"  {r['regle']:8s} {r['titre'][:44]:46s} {etat}", file=sys.stderr)
    print("\n  Un constat n'est pas un manquement : il le devient quand une règle\n"
          "  de la charte le dit. Voir le SKILL.md.", file=sys.stderr)


if __name__ == "__main__":
    main()
