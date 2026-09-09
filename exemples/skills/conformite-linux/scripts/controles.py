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

Bibliothèque standard seulement. La collecte n'est jamais modifiée.
"""
import argparse, base64, hashlib, json, os, re, sys, tarfile
from datetime import datetime, timezone

CONSTATS = []
_N = [0]


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
    c = {"id": f"C{_N[0]:04d}", "theme": theme, "constat": quoi, "valeur": valeur,
         "source": source, "methode": methode,
         "portee": portee or ("compte" if acteur else "poste")}
    for k, v in (("regle", regle), ("acteur", acteur), ("date", date),
                 ("question", question), ("note", note)):
        if v is not None:
            c[k] = v
    CONSTATS.append(c)
    return c


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

    def membres_tar(self, archive):
        self.lus.add(archive)
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m in t:
                    if m.isfile():
                        nom = m.name[2:] if m.name.startswith("./") else m.name
                        yield nom, t.extractfile(m).read()
        except (tarfile.TarError, OSError, EOFError, AttributeError) as e:
            print(f"  ! {os.path.basename(archive)} : {e}", file=sys.stderr)


def _compte_de(chemin, suffixe):
    m = re.search(rf'_([^_]+)_{suffixe}$', os.path.basename(chemin))
    return m.group(1) if m else "?"


# ── 1 · comptes et mots de passe ─────────────────────────────────────
def comptes(c):
    p = c.un("passwd", "COMPTES")
    homes, uid0 = {}, []
    if p:
        for l in c.texte(p).splitlines():
            ch = l.split(":")
            if len(ch) < 7:
                continue
            nom, uid, home, shell = ch[0], ch[2], ch[5], ch[6]
            if not uid.isdigit():
                continue
            if int(uid) == 0 and nom != "root":
                uid0.append(nom)
                constat("comptes", "compte disposant des droits de root",
                        f"{nom} (uid 0)", c.rel(p), "champ 3 de /etc/passwd",
                        acteur=nom,
                        question="la charte autorise-t-elle un second compte "
                                 "administrateur, et celui-ci est-il déclaré ?")
            if int(uid) >= 1000 and not shell.endswith(("nologin", "false")):
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
                if re.search(r'^\s*%?\S+\s+ALL\s*=\s*\(\s*ALL(\s*:\s*ALL)?\s*\)\s*ALL\s*$', l):
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


# ── 2 · le serveur SSH et le pare-feu ────────────────────────────────
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


def reseau(c):
    t = c.un("_reseau.tar.gz", "RESEAU")
    if not t:
        return
    pare_feu = []
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
        if re.search(r'(firewalld|ufw|iptables|nftables)', nom):
            pare_feu.append(nom)
        if base == "ufw.conf":
            m = re.search(r'^\s*ENABLED\s*=\s*(\w+)', txt, re.M | re.I)
            if m and m.group(1).lower() != "yes":
                constat("durcissement", "pare-feu ufw désactivé", m.group(0).strip(),
                        f"{c.rel(t)} → {nom}", "grep ENABLED dans ufw.conf",
                        question="la charte impose-t-elle un pare-feu actif ?")
    if not pare_feu:
        constat("durcissement", "aucune configuration de pare-feu",
                "ni firewalld, ni ufw, ni iptables, ni nftables", c.rel(t),
                "recherche des chemins de pare-feu dans l'archive réseau",
                question="la charte impose-t-elle un pare-feu ?",
                note="absence de CONFIGURATION : un pare-feu peut avoir été "
                     "piloté autrement. À confirmer avant d'en faire un manquement.")


# ── 3 · les secrets laissés en clair ─────────────────────────────────
def _cle_chiffree(blob):
    """Une clé privée SSH est-elle protégée par une phrase de passe ?

    Deux formats. L'ancien (PEM) l'annonce en clair par « Proc-Type: ENCRYPTED ».
    Le nouveau (openssh-key-v1) nomme son algorithme juste après l'en-tête :
    « none » veut dire aucune protection.
    """
    txt = blob.decode("utf-8", "replace", )
    if "PRIVATE KEY" not in txt:
        return None
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
FICHIERS_SECRETS = {
    ".netrc": "identifiants d'accès enregistrés en clair (.netrc)",
    ".git-credentials": "identifiants git enregistrés en clair",
    "credentials": "fichier d'identifiants (.aws/credentials ou équivalent)",
}


def secrets(c):
    for art in c.chercher("_artefacts.tar.gz", "COMPTES"):
        compte = _compte_de(art, "artefacts.tar.gz")
        for nom, blob in c.membres_tar(art):
            base = os.path.basename(nom)
            txt = blob.decode("utf-8", "replace")
            if base in FICHIERS_SECRETS and txt.strip():
                constat("secrets", FICHIERS_SECRETS[base], nom,
                        f"{c.rel(art)} → {nom}", "présence du fichier", acteur=compte,
                        question="la charte interdit-elle d'enregistrer des "
                                 "identifiants en clair ?")
            chiffree = _cle_chiffree(blob)
            if chiffree is False:
                constat("secrets", "clé privée SSH SANS phrase de passe", nom,
                        f"{c.rel(art)} → {nom}",
                        "lecture de l'en-tête de la clé : chiffrement « none »",
                        acteur=compte,
                        question="la charte impose-t-elle une phrase de passe sur "
                                 "les clés privées ?",
                        note="quiconque obtient ce fichier peut se connecter "
                             "partout où la clé est acceptée")
            elif chiffree is True:
                constat("secrets", "clé privée SSH protégée par une phrase de passe",
                        nom, f"{c.rel(art)} → {nom}", "en-tête de la clé",
                        acteur=compte, note="conforme à l'usage recommandé")
            if base.endswith(("_history", ".lesshst")):
                for l in txt.splitlines():
                    for motif, quoi in SECRETS:
                        if motif.search(l):
                            constat("secrets", quoi, l.strip()[:140],
                                    f"{c.rel(art)} → {nom}",
                                    f"motif « {motif.pattern[:40]} » dans l'historique",
                                    acteur=compte,
                                    question="la charte interdit-elle de saisir un "
                                             "secret en argument de commande ?",
                                    note="l'historique n'est pas daté par défaut : "
                                         "ne datez pas cette ligne sans autre source")
                            break


# ── les pièces où l'on cherche ───────────────────────────────────────
# Trois lecteurs, partagés par les contrôles fixes et par les règles fournies.
# Ce qui est lu ici est lu une fois, et de la même façon pour les deux.

BASES_NAVIGATEUR = ("places.sqlite", "History", "cookies.sqlite", "Cookies",
                    "Web Data", "Archived History")


def _bases_navigateur(c):
    """Les bases des navigateurs, en texte brut. Rend (compte, source, texte).

    Elles vivent dans DEUX archives, et l'oublier fait manquer un navigateur
    entier : Firefox est dans ~/.mozilla, donc dans _profils ; Chrome installé
    par paquet est dans ~/.config/google-chrome, donc dans _artefacts.

    Le fichier n'est pas ouvert en SQL : on cherche des motifs dans les octets.
    C'est moins fin qu'une requête, mais cela lit aussi les pages libérées —
    et cela n'écrit jamais dans la base, pas même un journal.
    """
    for suffixe in ("_profils.tar.gz", "_artefacts.tar.gz"):
        for arch in c.chercher(suffixe, "COMPTES"):
            compte = _compte_de(arch, suffixe[1:])
            for nom, blob in c.membres_tar(arch):
                if os.path.basename(nom) in BASES_NAVIGATEUR:
                    yield compte, f"{c.rel(arch)} → {nom}", \
                        blob.decode("latin-1", "replace")


def _chemins_inventaire(c):
    """Les chemins du dossier personnel. Rend (compte, source, [chemins]).

    L'inventaire est un « ls -lRa » : des en-têtes de dossier, puis des noms
    nus. Sans recoller les deux, un motif comme « .local/share/Steam/ » ne
    trouverait jamais rien. Le dossier du compte est remplacé par « ~ » : le
    point de montage de l'analyse n'a rien à faire dans un rapport.
    """
    for f in c.chercher("_inventaire.txt", "COMPTES"):
        compte = _compte_de(f, "inventaire.txt")
        racine, courant, chemins, dates = None, "", [], {}
        for l in c.texte(f, 8_000_000).splitlines():
            # un en-tête de dossier finit par « : » et n'a pas la forme d'une
            # ligne de ls — un fichier peut très bien s'appeler « notes: »
            if l.endswith(":") and not re.match(r'^[-dlbcpsD][-rwxsStT]{9}', l):
                brut = l[:-1]
                if racine is None:
                    racine = brut
                courant = "~" + brut[len(racine):] if brut.startswith(racine) else brut
                continue
            if not l or l.startswith("total "):
                continue
            ch = l.split(None, 8)
            if len(ch) < 8 or not re.match(r'^[-dlbcpsD][-rwxsStT]{9}', ch[0]):
                continue
            if re.match(r'^\d{4}-\d{2}-\d{2}$', ch[5]):    # ls --time-style=long-iso
                ch = l.split(None, 7)
                nom, quand = (ch[7] if len(ch) > 7 else None), " ".join(ch[5:7])
            else:                                          # « Jan  4 10:22 »
                nom, quand = (ch[8] if len(ch) > 8 else None), " ".join(ch[5:8])
            if not nom or nom in (".", ".."):
                continue
            nom = nom.split(" -> ", 1)[0]
            chemin = f"{courant}/{nom}" if courant else nom
            chemins.append(chemin)
            # la date telle que ls l'écrit, sans la convertir : elle n'a pas
            # d'année quand elle est récente, et sa langue est celle du poste
            # d'analyse. Elle se cite, elle ne se calcule pas.
            dates[chemin] = quand
        yield compte, c.rel(f), chemins, dates


def _lignes_paquets(c):
    """Ce qui est installé sur le POSTE. Rend (source, methode, [(date, ligne)]).

    La liste des paquets ne dit pas qui les a posés : ces constats sont de
    portée « poste ». Les journaux d'installation, eux, portent une date.
    """
    for f in c.chercher("_paquets.txt", "PAQUETS"):
        lignes = [(None, l) for l in c.texte(f, 8_000_000).splitlines()
                  if l.strip()]
        yield c.rel(f), "la liste des paquets installés", lignes
    for arch in c.chercher("_historique.tar.gz", "PAQUETS"):
        for nom, blob in c.membres_tar(arch):
            # history.sqlite de dnf est du binaire : le lire en texte ne
            # donnerait que des lignes illisibles dans les constats. Ses
            # journaux texte sont collectés à côté.
            if b"\x00" in blob[:4096]:
                continue
            txt = blob.decode("utf-8", "replace")
            lignes = []
            for l in txt.splitlines():
                if not l.strip():
                    continue
                m = re.match(r'^(\d{4}-\d{2}-\d{2}[ T|]\d{2}:\d{2}:\d{2})', l)
                lignes.append((m.group(1).replace("|", " ") if m else None, l))
            if lignes:
                yield f"{c.rel(arch)} → {nom}", \
                    "l'historique du gestionnaire de paquets", lignes


def _historiques(c):
    """Les commandes saisies par un compte. Rend (compte, source, [(date, ligne)]).

    bash ne date que si HISTTIMEFORMAT était posé : une ligne « #<epoch> »
    précède alors chaque commande. zsh, en mode étendu, écrit « : epoch:0;cmd ».
    Sans cela la date est None, et le constat doit le dire : la position d'une
    ligne dans le fichier ne prouve rien de son moment.
    """
    for art in c.chercher("_artefacts.tar.gz", "COMPTES"):
        compte = _compte_de(art, "artefacts.tar.gz")
        for nom, blob in c.membres_tar(art):
            if not os.path.basename(nom).endswith("_history"):
                continue
            lignes, quand = [], None
            for l in blob.decode("utf-8", "replace").splitlines():
                m = re.match(r'^#(\d{9,11})$', l)
                if m:
                    quand = _epoch_iso(int(m.group(1)))
                    continue
                m = re.match(r'^: (\d{9,11}):\d+;(.*)$', l)
                if m:
                    lignes.append((_epoch_iso(int(m.group(1))), m.group(2)))
                    continue
                if l.strip():
                    lignes.append((quand, l))
                    quand = None
            if lignes:
                yield compte, f"{c.rel(art)} → {nom}", lignes


def _epoch_iso(n):
    return datetime.fromtimestamp(n, timezone.utc).isoformat().replace("+00:00", "Z")


def _reseaux_sans_fil(c):
    """Les réseaux sans fil enregistrés. Rend un dict par réseau.

    NetworkManager garde un fichier par connexion ; « timestamps » y ajoute la
    date de la dernière association. Un profil peut être réservé à un compte
    (« permissions=user:… ») : alors le constat lui revient, sinon il est du
    poste.
    """
    t = c.un("_reseau.tar.gz", "RESEAU")
    if not t:
        return
    reseaux, dates = [], {}
    for nom, blob in c.membres_tar(t):
        txt = blob.decode("utf-8", "replace")
        if nom.endswith("NetworkManager/timestamps") or \
                os.path.basename(nom) == "timestamps":
            for m in re.finditer(r'^([0-9a-fA-F-]{36})=(\d+)', txt, re.M):
                dates[m.group(1).lower()] = int(m.group(2))
            continue
        if "system-connections" not in nom and "network-scripts" not in nom:
            continue
        ssid = None
        m = re.search(r'^\s*ssid\s*=\s*(.+?)\s*$', txt, re.M | re.I)
        if m:
            ssid = m.group(1)
            if re.fullmatch(r'(?:\d{1,3};)+', ssid):        # SSID non UTF-8
                ssid = bytes(int(x) for x in ssid.split(";") if x) \
                    .decode("utf-8", "replace")
        else:
            m = re.search(r'^\s*ESSID\s*=\s*"?([^"\n]+)"?', txt, re.M)
            if m:
                ssid = m.group(1)
        idc = re.search(r'^\s*id\s*=\s*(.+?)\s*$', txt, re.M)
        uuid = re.search(r'^\s*uuid\s*=\s*([0-9a-fA-F-]{36})', txt, re.M)
        perm = re.search(r'^\s*permissions\s*=\s*user:([^:;]+)', txt, re.M)
        reseaux.append({"ssid": ssid or (idc.group(1) if idc else
                                         os.path.splitext(os.path.basename(nom))[0]),
                        "id": idc.group(1) if idc else None,
                        "uuid": uuid.group(1).lower() if uuid else None,
                        "acteur": perm.group(1) if perm else None,
                        "source": f"{c.rel(t)} → {nom}"})
    for r in reseaux:
        q = dates.get(r["uuid"] or "")
        r["vu_le"] = (datetime.fromtimestamp(q, timezone.utc).isoformat()
                      .replace("+00:00", "Z")) if q else None
        yield r


# ── 4 · l'usage : ce qui a été visité, branché, installé ─────────────
# Familles indicatives. La charte décide de ce qui est permis : ce tableau ne
# sert qu'à ranger les domaines pour la lecture, jamais à les condamner.
FAMILLES = [
    ("de stockage personnel en ligne", re.compile(
        r'(wetransfer|transfernow|swisstransfer|dropbox|drive\.google|mega\.nz'
        r'|onedrive|1fichier|smash\.|grosfichiers|filesender)', re.I)),
    ("de messagerie personnelle", re.compile(
        r'(mail\.google|outlook\.live|protonmail|proton\.me|yahoo.*mail|laposte\.net'
        r'|orange\.fr/webmail|free\.fr/webmail|gmx\.|zoho.*mail)', re.I)),
    ("d'intelligence artificielle générative", re.compile(
        r'(chatgpt|openai\.com|claude\.ai|anthropic\.com|gemini\.google|mistral\.ai'
        r'|perplexity\.ai|copilot\.microsoft)', re.I)),
    ("de réseau social", re.compile(
        r'(facebook|instagram|twitter|x\.com|linkedin|tiktok|snapchat|reddit)', re.I)),
    ("de dépôt de code public", re.compile(
        r'(github\.com|gitlab\.com|bitbucket|pastebin|gist\.github)', re.I)),
    ("d'accès distant grand public", re.compile(
        r'(teamviewer|anydesk|logmein|ngrok|localtunnel)', re.I)),
]


def usage(c):
    """Ce qui a servi. Rien n'est qualifié : les familles rangent, la charte juge."""
    vus = {}
    for compte, source, texte in _bases_navigateur(c):
        for famille, motif in FAMILLES:
            for m in sorted(set(motif.findall(texte))):
                cle = (compte, famille, m.lower())
                if cle in vus:
                    continue
                vus[cle] = True
                constat("usage", f"service {famille} présent dans un "
                        "profil de navigateur", m, source,
                        "recherche de motifs de domaines dans la base du "
                        "navigateur (sans l'ouvrir en SQL)",
                        acteur=compte,
                        question=f"la charte encadre-t-elle l'usage d'un "
                                 f"service {famille} sur un poste "
                                 f"professionnel ?",
                        note="présence dans la base : la date exacte se lit "
                             "dans faits.jsonl du skill forensic-linux")

    # Supports amovibles et logiciels hors gestionnaire : le journal les porte.
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        txt = c.texte(j)
        cles = set(re.findall(r'/run/media/([^/\s]+)/(\S+)', txt))
        for compte, etiquette in sorted(cles):
            constat("usage", "support amovible monté", etiquette,
                    c.rel(j), "chemins /run/media/<compte>/ dans le journal",
                    acteur=compte,
                    question="la charte encadre-t-elle l'usage de supports "
                             "amovibles, et exige-t-elle qu'ils soient chiffrés ?")

    for compte, source, chemins, _ in _chemins_inventaire(c):
        for m in sorted({ch for ch in chemins
                         if re.search(r'\.(?:AppImage|deb|rpm|exe|msi)$', ch, re.I)}):
            constat("usage", "programme installable présent dans un dossier "
                    "personnel", m, source, "recherche d'extensions dans "
                    "l'inventaire du profil", acteur=compte,
                    question="la charte réserve-t-elle l'installation de "
                             "logiciels au service informatique ?")


# ── 5 · les règles fournies ──────────────────────────────────────────
# Une règle de la charte n'est pas un contrôle : c'est une phrase. La traduire
# en quelque chose que l'on cherche dans une collecte est une INTERPRÉTATION, et
# un lecteur doit pouvoir la contester. D'où ce fichier de règles, écrit à la
# main, lisible par qui n'écrit pas de Python : la traduction y est visible, et
# elle se corrige sans toucher au code.
#
# Le format est décrit dans references/regles/usage-non-professionnel.regles.

CLES_REGLE = ("regle", "titre", "texte", "portee", "theme")
CLES_INDICE = ("domaine", "programme", "fichier", "commande", "wifi", "horaire")

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
}

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
                if cle == "horaire":
                    m = RE_PLAGE.match(valeur)
                    if not m:
                        sys.exit(f"{chemin}:{num} : horaire illisible — attendu "
                                 "« lun-ven 08:00-19:00 »")
                    d, f = JOURS.index(m.group(1).lower()), JOURS.index(m.group(2).lower())
                    jours = {j % 7 for j in range(d, f + 1 if f >= d else f + 8)}
                    motif = (jours, int(m.group(3)) * 60 + int(m.group(4)),
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


def _grouper(textes, motif, exemples=True):
    """Groupe les trouvailles par ce qui a été trouvé : {trouvé: (n, exemples)}.

    Un dossier de films donne mille lignes pour un seul indice. Grouper rend le
    constat lisible et borné, sans perdre le compte ni les exemples. Sur une
    base de navigateur — un seul texte de plusieurs dizaines de Mo — l'exemple
    serait le fichier entier : on ne garde alors que le compte.
    """
    par = {}
    for t in textes:
        for m in motif.finditer(t):
            v = m.group(0)
            n, ex = par.get(v.lower(), (0, []))
            if exemples and len(ex) < 5 and t not in ex:
                ex.append(t)
            par[v.lower()] = (n + 1, ex)
    return par


_DEJA = set()
_FUSEAU = [None]


def _local(iso):
    """Une date UTC (« …Z ») dans le fuseau du poste, quand on le connaît.

    Les faits écrivent l'UTC ; un rapport se lit dans l'heure du poste. La
    conversion est faite ici, une fois, pour toutes les dates d'un constat.
    """
    if not (isinstance(iso, str) and _FUSEAU[0] and
            (iso.endswith("Z") or re.search(r'[+-]\d\d:\d\d$', iso))):
        return iso
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")) \
            .astimezone(_FUSEAU[0]).isoformat()
    except ValueError:
        return iso


def _poser(r, cle, etiquette, brut, quoi, valeur, source, methode,
           acteur=None, portee=None, date=None, note=None):
    # Deux motifs d'une même règle attrapent souvent la même chose — « mcdo »
    # et « mcdonalds.?free » sur le même réseau. Une pièce, un constat.
    empreinte_c = (r["regle"], cle, source, str(valeur).lower(), acteur)
    if empreinte_c in _DEJA:
        return None
    _DEJA.add(empreinte_c)
    date = _local(date)
    detail = f"ce que cet indice établit : {PREUVE[cle]}"
    if etiquette:
        detail = f"catégorie donnée par la règle : {etiquette}. " + detail
    if note:
        detail = note + ". " + detail
    return constat(
        r["theme"], quoi, valeur, source, methode, regle=r["regle"],
        acteur=acteur, date=date,
        portee=portee or (r["portee"] if acteur else "poste"),
        question=f"règle {r['regle']} « {r['titre']} » — l'indice « {brut} » "
                 "traduit-il fidèlement ce que dit la règle ?",
        note=detail)


def appliquer_regles(c, regles, faits=None, fuseau=None):
    """Cherche dans la collecte les indices que les règles désignent."""
    besoin = {cle for r in regles for cle, _, _, _ in r["indices"]}
    nav = list(_bases_navigateur(c)) if "domaine" in besoin else []
    inv = list(_chemins_inventaire(c)) if besoin & {"fichier", "programme"} else []
    paq = list(_lignes_paquets(c)) if "programme" in besoin else []
    shell = list(_historiques(c)) if "commande" in besoin else []
    ondes = list(_reseaux_sans_fil(c)) if "wifi" in besoin else []
    visites = _visites_par_compte(faits) if faits and "domaine" in besoin else {}
    _FUSEAU[0] = fuseau

    for r in regles:
        avant, absentes = len(CONSTATS), []
        for cle, motif, etiquette, brut in r["indices"]:
            if cle == "domaine":
                if not nav:
                    absentes.append("aucune base de navigateur dans la collecte")
                    continue
                for compte, source, texte in nav:
                    for v, (n, _) in sorted(
                            _grouper([texte], motif, exemples=False).items()):
                        date, note = None, f"{n} occurrence(s) dans la base"
                        # les faits du skill forensic datent la visite — et
                        # distinguent une visite d'un téléchargement
                        liees = [f for f in visites.get(compte, ())
                                 if v in (f["valeur"] + " " + (f.get("note") or "")).lower()]
                        if liees:
                            dates = sorted(f["horodatage"] for f in liees)
                            date = dates[-1]
                            note += (f" ; {len(liees)} fait(s) daté(s) dans faits.jsonl, "
                                     f"du {_local(dates[0])} au {_local(dates[-1])} : "
                                     + ", ".join(f["id"] for f in liees[:8]))
                            charges = [f["id"] for f in liees
                                       if f["categorie"] == "telechargement"]
                            if charges:
                                note += (" — dont un TÉLÉCHARGEMENT ("
                                         + ", ".join(charges[:4]) + ") : plus qu'une "
                                         "consultation, à citer comme tel")
                        elif faits:
                            note += (" ; aucun fait daté ne cite ce domaine : il "
                                     "vient des cookies, d'un favori ou d'une page "
                                     "libérée — pas d'une visite datée")
                        else:
                            note += " ; la date se lit avec --faits"
                        _poser(r, cle, etiquette, brut,
                               "domaine présent dans une base de navigateur",
                               v, source,
                               f"motif « {brut} » cherché dans les octets de la "
                               "base, sans l'ouvrir en SQL",
                               acteur=compte, date=date, note=note)

            elif cle == "fichier":
                if not inv:
                    absentes.append("aucun inventaire de dossier personnel")
                    continue
                for compte, source, chemins, dates in inv:
                    for v, (n, ex) in sorted(_grouper(chemins, motif).items()):
                        _poser(r, cle, etiquette, brut,
                               "fichier présent dans le dossier personnel",
                               v, source,
                               f"motif « {brut} » cherché dans les chemins de "
                               "l'inventaire (ls -lRa)",
                               acteur=compte,
                               note=f"{n} chemin(s), par exemple : "
                                    + " ; ".join(_avec_date(x, dates) for x in ex)
                                    + ". La date entre parenthèses est celle que "
                                    "ls affiche : modification, sans année si récente")

            elif cle == "programme":
                if not inv and not paq:
                    absentes.append("ni liste de paquets ni inventaire")
                    continue
                for source, methode, lignes in paq:
                    trouve = {}
                    for date, ligne in lignes:
                        for m in motif.finditer(ligne):
                            v = m.group(0).lower()
                            if v not in trouve:
                                trouve[v] = (date, ligne)
                    for v, (date, ligne) in sorted(trouve.items()):
                        _poser(r, cle, etiquette, brut,
                               "programme installé sur le poste", v, source,
                               f"motif « {brut} » cherché dans la {methode}",
                               portee="poste", date=date,
                               note="la liste des paquets ne dit pas quel compte "
                                    "a demandé l'installation : la portée est "
                                    "le poste. Ligne : " + ligne.strip()[:120])
                for compte, source, chemins, dates in inv:
                    for v, (n, ex) in sorted(_grouper(chemins, motif).items()):
                        _poser(r, cle, etiquette, brut,
                               "programme présent dans le dossier personnel",
                               v, source,
                               f"motif « {brut} » cherché dans les chemins de "
                               "l'inventaire (ls -lRa)",
                               acteur=compte,
                               note=f"{n} chemin(s), par exemple : "
                                    + " ; ".join(_avec_date(x, dates) for x in ex))

            elif cle == "commande":
                if not shell:
                    absentes.append("aucun historique d'interpréteur")
                    continue
                for compte, source, lignes in shell:
                    trouve = {}
                    for date, ligne in lignes:
                        for m in motif.finditer(ligne):
                            v = m.group(0).lower()
                            n, ex, quand = trouve.get(v, (0, [], []))
                            if len(ex) < 5:
                                ex.append(ligne.strip()[:100])
                            if date:
                                quand.append(date)
                            trouve[v] = (n + 1, ex, quand)
                    for v, (n, ex, quand) in sorted(trouve.items()):
                        quand.sort()
                        if quand:
                            note = (f"{n} saisie(s), {len(quand)} datée(s) du "
                                    f"{_local(quand[0])} au {_local(quand[-1])} "
                                    "(HISTTIMEFORMAT posé)")
                        else:
                            note = (f"{n} saisie(s), AUCUNE datée : l'historique "
                                    "n'a pas de dates, ne lui en donnez pas")
                        _poser(r, cle, etiquette, brut,
                               "commande saisie dans l'interpréteur", v, source,
                               f"motif « {brut} » cherché ligne à ligne dans "
                               "l'historique de l'interpréteur",
                               acteur=compte, date=quand[-1] if quand else None,
                               note=note + ". Par exemple : " + " ; ".join(ex))

            elif cle == "wifi":
                if not ondes:
                    absentes.append("aucun profil de connexion réseau")
                    continue
                for o in ondes:
                    cible = " ".join(x for x in (o["ssid"], o["id"]) if x)
                    if not motif.search(cible):
                        continue
                    _poser(r, cle, etiquette, brut,
                           "réseau sans fil enregistré sur le poste",
                           o["ssid"], o["source"],
                           f"motif « {brut} » cherché dans le SSID des profils "
                           "NetworkManager",
                           acteur=o["acteur"], date=o["vu_le"],
                           portee="compte" if o["acteur"] else "poste",
                           note=("date de la dernière association, lue dans "
                                 "var/lib/NetworkManager/timestamps"
                                 if o["vu_le"] else
                                 "aucune date : le fichier « timestamps » de "
                                 "NetworkManager manque ou ne connaît pas ce profil"))

            elif cle == "horaire":
                jours, deb, fin = motif
                if faits is None:
                    absentes.append("les heures demandent --faits (faits.jsonl "
                                    "du skill forensic-linux)")
                    continue
                _horaires(c, r, cle, etiquette, brut, jours, deb, fin,
                          faits, fuseau)

        trouves = len(CONSTATS) - avant
        for quoi in dict.fromkeys(absentes):
            constat("limite", f"règle {r['regle']} : {quoi}",
                    r["titre"], c.prefix,
                    "recherche des indices de la règle dans la collecte",
                    regle=r["regle"],
                    note="un indice de cette règle n'a pas pu être cherché ; "
                         "l'absence de la pièce n'est pas l'absence de "
                         "manquement. Voir references/ou-chercher.md du "
                         "skill forensic-linux pour la reprendre")
        if trouves == 0:
            if not absentes:
                constat("conforme",
                        f"règle {r['regle']} : aucun indice trouvé",
                        r["titre"], c.prefix,
                        "recherche, dans les pièces disponibles, des "
                        + str(len(r["indices"])) + " indices de la règle",
                        regle=r["regle"],
                        note="aucun indice ne prouve pas le respect de la "
                             "règle : les indices sont ceux qu'on a su écrire, "
                             "et un historique s'efface")


def _avec_date(chemin, dates):
    return f"{chemin} ({dates[chemin]})" if dates.get(chemin) else chemin


def _visites_par_compte(faits):
    """Les faits de navigation datés, par compte : de quoi dater un domaine."""
    par = {}
    for f in faits:
        if f.get("categorie") in ("navigation", "telechargement") and \
                f.get("horodatage") and f.get("acteur"):
            par.setdefault(f["acteur"], []).append(f)
    return par


def _horaires(c, r, cle, etiquette, brut, jours, deb, fin, faits, fuseau):
    """Les ouvertures de session hors des heures ouvrées, groupées par journée."""
    par, lus = {}, 0
    for f in faits:
        if f.get("categorie") != "evenement" or not f.get("horodatage"):
            continue
        if "ouverture de session" not in f.get("fait", ""):
            continue
        try:
            q = datetime.fromisoformat(f["horodatage"].replace("Z", "+00:00"))
        except ValueError:
            continue
        lus += 1
        if q.tzinfo and fuseau:
            q = q.astimezone(fuseau)
        minute = q.hour * 60 + q.minute
        if q.weekday() in jours and deb <= minute < fin:
            continue
        cle_j = (f.get("acteur") or "?", q.date().isoformat())
        par.setdefault(cle_j, []).append((q.strftime("%H:%M"), f.get("id", "")))
    if not lus:
        constat("limite", f"règle {r['regle']} non vérifiée : aucune ouverture "
                "de session datée dans faits.jsonl", r["titre"], c.prefix,
                "lecture des faits de catégorie « evenement »", regle=r["regle"],
                note="wtmp absent, illisible, ou étape de collecte non jouée")
        return
    nom_fuseau = str(fuseau) if fuseau else "celui que portent les faits"
    for (qui, jour), heures in sorted(par.items()):
        heures.sort()
        _poser(r, cle, etiquette, brut,
               "session ouverte hors des heures indiquées",
               f"{jour} ({JOURS[datetime.fromisoformat(jour).weekday()]}) : "
               + ", ".join(h for h, _ in heures),
               "faits.jsonl (skill forensic-linux)",
               f"heures ouvrées « {brut} » comparées à l'horodatage des "
               f"ouvertures de session, lues dans le fuseau {nom_fuseau}",
               acteur=None if qui == "?" else qui, date=jour,
               note=f"{len(heures)} ouverture(s) : "
                    + ", ".join(i for _, i in heures if i))


# ── mise en ordre ────────────────────────────────────────────────────
def _fuseau(demande, faits):
    """Dans quel fuseau lire les heures.

    L'ordre est celui de la certitude : ce que l'analyste impose, puis ce que
    le poste déclarait (/etc/localtime, relevé par le skill forensic-linux),
    puis rien — et alors les heures se lisent telles que les faits les portent,
    ce que la méthode du constat dira.
    """
    nom = demande
    if not nom and faits:
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


def empreinte(chemin):
    h = hashlib.sha256()
    with open(chemin, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


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
    for etape, fn in (("comptes et mots de passe", comptes),
                      ("réseau et durcissement", reseau),
                      ("secrets", secrets), ("usage", usage)):
        avant = len(CONSTATS)
        try:
            fn(c)
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! {etape} : {type(e).__name__} {e}", file=sys.stderr)
        print(f"  {etape:26s} {len(CONSTATS) - avant:4d} constats", file=sys.stderr)

    regles, faits = [], None
    if args.regles:
        regles = lire_regles(args.regles)
        if args.faits:
            faits = lire_faits(args.faits)
        fuseau = _fuseau(args.fuseau, faits)
        avant = len(CONSTATS)
        appliquer_regles(c, regles, faits, fuseau)
        print(f"  {'règles fournies':26s} {len(CONSTATS) - avant:4d} constats "
              f"({len(regles)} règles)", file=sys.stderr)

    with open(args.sortie, "w", encoding="utf-8") as fh:
        for x in CONSTATS:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")

    man = os.path.splitext(args.sortie)[0] + "-manifeste.json"
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
                   "constats_sha256": hashlib.sha256(
                       open(args.sortie, "rb").read()).hexdigest(),
                   "pieces_lues": {c.rel(p): {"sha256": empreinte(p),
                                              "octets": os.path.getsize(p)}
                                   for p in sorted(c.lus) if os.path.isfile(p)}},
                  fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    par = {}
    for x in CONSTATS:
        par[x["theme"]] = par.get(x["theme"], 0) + 1
    print(f"\n{len(CONSTATS)} constats → {args.sortie}", file=sys.stderr)
    print(f"  empreintes → {man}", file=sys.stderr)
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(par.items())), file=sys.stderr)
    if regles:
        print("", file=sys.stderr)
        for r in regles:
            n = sum(1 for x in CONSTATS if x.get("regle") == r["regle"]
                    and x["theme"] not in ("limite", "conforme"))
            manque = any(x.get("regle") == r["regle"] and x["theme"] == "limite"
                         for x in CONSTATS)
            etat = f"{n} constats" if n else "aucun indice"
            if manque:
                etat += " — indices non cherchés, pièce absente"
            print(f"  {r['regle']:8s} {r['titre'][:44]:46s} {etat}", file=sys.stderr)
    print("\n  Un constat n'est pas un manquement : il le devient quand une règle\n"
          "  de la charte le dit. Voir le SKILL.md.", file=sys.stderr)


if __name__ == "__main__":
    main()
