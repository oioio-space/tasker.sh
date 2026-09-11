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
import argparse, base64, bz2, collections, csv, functools, gzip, hashlib, json, lzma
import os, re, sys, tarfile, zlib
from datetime import datetime, timezone

CONSTATS = []
COLONNES_CSV = ("id", "theme", "regle", "constat", "valeur", "date", "acteur", "portee",
                "source", "methode", "question", "note")
RE_CONTROLE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
# Un nom de fichier n'est PAS forcément de l'UTF-8 : un disque à noms latin-1,
# un nom forgé, et os.walk comme tarfile rendent les octets indécodables sous
# forme de « demi-codets » (\udce9). json.dumps les laisse passer, et c'est
# l'écriture sur le flux UTF-8 qui lève — à la toute fin, après toute
# l'extraction. Mesuré : traceback, faits.jsonl tronqué en plein milieu, ni
# CSV ni manifeste. Un seul fichier mal nommé sur le disque examiné emportait
# donc l'analyse entière.


def _propre(v):
    """Une valeur tirée d'une pièce peut porter des octets de contrôle — un
    contexte pris dans une base binaire, un nom de fichier forgé. Ils n'ont
    rien à faire dans un rapport, un CSV ou un terminal : un point médian.

    Les octets d'un nom de fichier qui n'est pas de l'UTF-8 sont rendus sous
    leur forme \\xNN : lisible, sans ambiguïté sur le fait que le nom n'est pas
    du texte, et surtout écrivable — sans quoi c'est toute la sortie qui est
    perdue à la dernière ligne du programme.

    Le repérage se fait par encode() en try/except, et non par une expression :
    _propre est appelée sur CHAQUE champ de CHAQUE fait, et une seconde regex y
    coûtait 34 % du temps de fait() là où celle-ci en coûte 11.
    """
    if not isinstance(v, str):
        return v
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        v = v.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    return RE_CONTROLE.sub("·", v)


def constat(theme, quoi, valeur, source, methode, acteur=None, portee=None,
            question=None, note=None, regle=None, date=None):
    """Pose un constat.

    theme    la famille : comptes, authentification, secrets, durcissement,
             usage, partage
    quoi     ce qui est observé, formulé sans jugement
    portee   « poste » ou « compte » — un manquement de poste n'est imputable
             à personne en particulier
    question ce qu'une règle devra dire pour en faire un manquement ; quand la
             règle est fournie, ce que sa traduction en indice suppose
    regle    l'identifiant de la règle cherchée, quand il y en a une
    date     l'horodatage porté par la pièce elle-même, quand elle en porte un
    """
    c = {"id": f"C{len(CONSTATS) + 1:04d}", "theme": theme, "constat": quoi,
         "valeur": valeur, "source": source, "methode": methode,
         "portee": portee or ("compte" if acteur else "poste")}
    for k, v in (("regle", regle), ("acteur", acteur), ("date", date),
                 ("question", question), ("note", note)):
        if v is not None:
            c[k] = v
    c = {k: _propre(v) for k, v in c.items()}
    CONSTATS.append(c)
    return c


def _epoch_iso(n):
    return datetime.fromtimestamp(n, timezone.utc).isoformat().replace("+00:00", "Z")


def instant(h, fuseau=None):
    """Un horodatage de fait ou de constat, lu comme un instant comparable.

    Trois formes existent dans les faits : « …Z » (epoch, UTC), « …+01:00 »
    (journalctl), et rien du tout — une ligne syslog, dpkg.log, la sortie de
    « last » : c'est alors l'heure du poste, et on la lit dans son fuseau
    quand on le connaît, en UTC sinon. Une seule fonction pour les trois, ou
    chaque consommateur se trompe à son tour.
    """
    if not h:
        return None
    try:
        d = datetime.fromisoformat(str(h).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=fuseau or timezone.utc)
    return d.astimezone(fuseau or timezone.utc)


def _compte_de(chemin, suffixe):
    """PREFIX_<compte>_<suffixe> → compte."""
    m = re.search(rf'_([^_]+)_{re.escape(suffixe)}$', os.path.basename(chemin))
    return m.group(1) if m else "?"


# Les compresseurs que logrotate et les gestionnaires de paquets emploient.
# .gz est le défaut, mais .xz est celui de Debian pour les vieilles rotations
# et .bz2 se rencontre encore. UNE table : None veut dire « connu, mais pas
# ouvrable ici » — c'est là qu'on éditera le jour où zstd sera pris en charge,
# et non dans une seconde liste qui devrait rester complémentaire de celle-ci.
_DECOMPRESSEURS = {".gz": gzip.decompress, ".xz": lzma.decompress,
                   ".lzma": lzma.decompress, ".bz2": bz2.decompress,
                   ".zst": None, ".lz4": None, ".Z": None}


def _non_lu(nom, source, pourquoi):
    constat("limite", "membre d'archive non décompressé", nom, source or nom,
            pourquoi, portee="poste",
            note="son contenu n'est PAS dans l'analyse")


def texte_de(nom, blob, source=None):
    """Le texte d'un membre d'archive, ou None s'il n'en est pas un :
    décompressé s'il le faut, écarté s'il est binaire.

    Un membre qu'on ne sait pas ouvrir laisse un constat « limite ». Il n'en
    laissait aucun, et seul .gz était connu : un history.log.2.xz installé et
    présent disparaissait de l'analyse SANS un mot, la règle qui le cherchait
    rendant « 2 constats » au lieu de 3. Le skill forensic lit les mêmes
    membres avec les mêmes compresseurs ; les deux rapports se contredisaient
    sur la même pièce.
    """
    suffixe = os.path.splitext(nom)[1]
    if suffixe in _DECOMPRESSEURS:
        ouvrir = _DECOMPRESSEURS[suffixe]
        if ouvrir is None:
            _non_lu(nom, source, "compresseur non disponible")
            return None
        try:
            blob = ouvrir(blob)
        except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error) as e:
            # zlib.error ne descend d'aucune des autres, et c'est l'exception
            # normale d'un .gz au corps deflate abîmé : elle remontait jusqu'à
            # etape(), qui vidait la liste des pièces — et le rapport annonçait
            # alors « pièce absente » pour un fichier bel et bien présent et
            # lisible. Une affirmation fausse, pas seulement une omission.
            _non_lu(nom, source, f"{type(e).__name__} à l'ouverture")
            return None
    if b"\x00" in blob[:4096]:
        return None
    return blob.decode("utf-8", "replace")


class Collecte:
    def __init__(self, racine):
        self.racine = os.path.abspath(racine)
        self.prefix = os.path.basename(self.racine)
        self.lus = set()
        self.abimees = set()      # archives dont la lecture s'est arrêtée net
        if not os.path.isdir(self.racine):
            sys.exit(f"pas un dossier : {self.racine}")

    def rel(self, chemin):
        """Le chemin tel qu'il sera CITÉ : jamais celui par lequel on ouvre.

        Le repli des demi-codets a donc lieu ici, une fois pour toutes — et
        non à chaque écriture. Le journal de reprise, le manifeste et les
        sources des faits portent alors tous la même chaîne, écrivable."""
        return _propre(os.path.relpath(chemin, self.racine))

    def chercher(self, motif, sous=None):
        base = os.path.join(self.racine, sous) if sous else self.racine
        t = []
        for d, _, fichiers in os.walk(base):
            t += [os.path.join(d, n) for n in fichiers if motif in n]
        return sorted(t)

    def un(self, motif, sous=None):
        t = self.chercher(motif, sous)
        return t[0] if t else None

    @functools.lru_cache(maxsize=None)
    def texte(self, chemin, limite=400_000_000):
        """Le contenu d'une pièce, avec un plafond qui SE DIT s'il mord.

        Il était à 8 Mo, en silence. usage() cherche les supports amovibles
        dans le journal avec ce texte-là : au-delà, le journal était coupé sans
        un mot et les montages de la fin disparaissaient. Mesuré sur un journal
        de 9 Mo, une clé branchée en début de fichier ressortait, celle de la
        fin non. Le skill forensic lit la même pièce avec 400 Mo : la divergence
        entre les deux skills valait un facteur cinquante.
        """
        try:
            with open(chemin, "rb") as fh:
                self.lus.add(chemin)
                brut = fh.read(limite)
                if len(brut) == limite and os.path.getsize(chemin) > limite:
                    constat("limite", "pièce lue en partie seulement",
                            self.rel(chemin), self.rel(chemin),
                            f"lecture bornée à {limite // 1_000_000} Mo",
                            portee="poste",
                            note="ce qui suit n'est PAS dans l'analyse")
                return brut.decode("utf-8", "replace")
        except OSError:
            return ""

    def lignes(self, chemin):
        """Les lignes d'un gros fichier texte, sans le tenir en mémoire."""
        self.lus.add(chemin)
        try:
            with open(chemin, encoding="utf-8", errors="replace") as fh:
                for l in fh:
                    yield l.rstrip("\n")
        except OSError:
            return

    def membres_tar(self, archive, garde=None, liens=False):
        """(nom, contenu) des fichiers d'un .tar.gz — ceux que garde(nom) accepte.

        Le filtre passe AVANT la lecture : une archive de profils porte des
        caches de centaines de Mo qu'aucun contrôle ne regarde.

        Avec liens=True, les LIENS symboliques sont rendus eux aussi, leur
        cible en guise de contenu. Certaines pièces ne sont QUE des liens :
        /etc/apparmor.d/disable/ n'en contient pas d'autres, et sans cela le
        contrôle ne trouvait jamais rien.
        """
        self.lus.add(archive)
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m in t:
                    if not (m.isfile() or (liens and m.issym())):
                        continue
                    nom = m.name[2:] if m.name.startswith("./") else m.name
                    if garde and not garde(nom):
                        continue
                    if m.issym():
                        yield nom, m.linkname.encode("utf-8", "replace")
                        continue
                    fh = t.extractfile(m)
                    if fh is not None:
                        yield nom, fh.read()
        except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
            # Un mot sur stderr ne suffit pas : le rapport est bâti sur les
            # constats, et il ne portait aucune trace que les membres suivant
            # le point de rupture n'avaient pas été lus. Une seule fois par
            # archive — certaines sont parcourues deux fois.
            print(f"  ! {os.path.basename(archive)} : {e}", file=sys.stderr)
            if archive not in self.abimees:
                self.abimees.add(archive)
                constat("limite", "archive lue en partie seulement",
                        self.rel(archive), self.rel(archive),
                        f"{type(e).__name__} pendant le parcours", portee="poste",
                        note="les membres qui suivent le point de rupture ne "
                             "sont PAS dans l'analyse")


# ── 1 · comptes et mots de passe ─────────────────────────────────────
RE_SUDO_TOUT = re.compile(r'^\s*%?\S+\s+ALL\s*=\s*\(\s*ALL(\s*:\s*ALL)?\s*\)\s*ALL\s*$')
DROITS_LUS = ("shadow", "sudoers", "config", "login.defs", "pwquality.conf")
# Ce que PAM impose, ou n'impose pas. L'absence d'une règle est un constat
# autant que sa présence : un poste sans pam_faillock n'a AUCUNE limite au
# nombre d'essais de mot de passe.
PAM = [
    ("pam_pwquality.so", "pam_cracklib.so", "aucune exigence de robustesse des mots de passe",
     "la charte fixe-t-elle une longueur ou une complexité minimale ?"),
    ("pam_faillock.so", "pam_tally2.so", "aucun blocage du compte après des échecs répétés",
     "la charte impose-t-elle un verrouillage après plusieurs échecs ?"),
]
# Copie conforme du motif de forensic-linux/scripts/extraire.py : les deux
# skills doivent nommer le même support de la même façon.
RE_MEDIA = re.compile(r'(?:/run)?/media/([^/\s]+)/([^\s,;:]*[^\s,;:.])')
RE_NULLOK = re.compile(r'^\s*[^#\n]*\bnullok\b', re.M)
RE_MINLEN = re.compile(r'\bminlen\s*=\s*(\d+)')


def comptes(c):
    """Rend l'ensemble des comptes locaux, en posant les constats de comptes."""
    p = c.un("passwd", "COMPTES")
    homes, locaux, trouves_pam, modules_pam = {}, set(), set(), set()
    if p:
        for l in c.texte(p).splitlines():
            ch = l.split(":")
            if len(ch) < 7 or not ch[2].isdigit():
                continue
            nom, uid, home, shell = ch[0], int(ch[2]), ch[5], ch[6]
            locaux.add(nom)
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
        return locaux
    for nom, blob in c.membres_tar(d, lambda n: os.path.basename(n) in DROITS_LUS
                                   or "/sudoers.d/" in n or "/pam.d/" in n
                                   or "/apparmor.d/disable/" in n, liens=True):
        txt = blob.decode("utf-8", "replace")
        base = os.path.basename(nom)
        modules_pam.update(m.group(0) for m in re.finditer(r'pam_\w+\.so', txt))
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
        elif base == "pwquality.conf" or "/pam.d/" in nom:
            trouves_pam.add(nom)
            for m in RE_NULLOK.finditer(txt):
                constat("authentification",
                        "PAM accepte un mot de passe vide (nullok)", m.group(0).strip()[:120],
                        f"{c.rel(d)} → {nom}", "mot-clé nullok dans une règle PAM",
                        question="la charte exige-t-elle un mot de passe sur tout compte ?",
                        note="un compte au champ de mot de passe vide peut alors ouvrir "
                             "une session sans rien saisir")
            # « minlen = 12 » dans pwquality.conf, « pam_pwquality.so minlen=6 »
            # dans /etc/pam.d : c'est un ARGUMENT de module, pas un début de ligne
            for l in txt.splitlines():
                if l.lstrip().startswith("#"):
                    continue
                for m in RE_MINLEN.finditer(l):
                    if int(m.group(1)) < 8:
                        constat("authentification", "longueur minimale de mot de passe faible",
                                f"minlen {m.group(1)}", f"{c.rel(d)} → {nom}",
                                f"minlen dans « {l.strip()[:100]} »",
                                question="la charte fixe-t-elle une longueur minimale ?")
        elif "/apparmor.d/disable/" in nom:
            constat("durcissement", "profil AppArmor désactivé", os.path.basename(nom),
                    f"{c.rel(d)} → {nom}",
                    "présence du lien dans apparmor.d/disable/ (un lien, pas un fichier)",
                    question="la charte impose-t-elle le maintien des protections du "
                             "système ?",
                    note="le profil existe mais ne s'applique pas ; qui l'a désactivé "
                         "et quand ne se lit pas ici")
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

    # Ce qui n'est PAS là : sur un poste dont on a bien lu la configuration PAM,
    # l'absence d'un module est un fait, pas une lacune de la collecte.
    if trouves_pam:
        for premier, second, quoi, question in PAM:
            if not ({premier, second} & modules_pam):
                constat("authentification", quoi,
                        f"ni {premier} ni {second} dans /etc/pam.d", c.rel(d),
                        f"recherche des modules PAM dans {len(trouves_pam)} fichiers de "
                        "/etc/pam.d et /etc/security", question=question,
                        note="le poste n'impose donc rien de ce côté ; la politique peut "
                             "venir d'ailleurs (annuaire, image maîtresse) — à confirmer "
                             "avant d'en faire un manquement")
    return locaux


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
# ── commun ── (identique dans forensic-linux et conformite-linux : chaque skill
# s'installe seul, et le README dit comment vérifier que le bloc n'a pas dérivé)
RE_SSID_NM = re.compile(r'^\s*ssid\s*=\s*(.+?)\s*$', re.M | re.I)
RE_SSID_WPA = re.compile(r'^\s*ssid\s*=\s*"?([^"\n]+)"?', re.M)
RE_ESSID = re.compile(r'^\s*ESSID\s*=\s*"?([^"\n]+)"?', re.M)
RE_ACCESS_POINTS = re.compile(r'^\s*access-points:\s*$', re.M)
RE_POINT_NETPLAN = re.compile(r'^\s{2,}"?([^"\s:][^":\n]*)"?:\s*$', re.M)


def ssids_de(nom, txt):
    """Les réseaux sans fil qu'un membre de l'archive réseau déclare, quel que
    soit le gestionnaire. Rend [(ssid, méthode)].

    NetworkManager écrit un SSID non UTF-8 en octets décimaux « 1;2;3; » ;
    iwd nomme le fichier par le SSID, en hexadécimal « =4d63… » quand il sort
    de [A-Za-z0-9_-] ; netplan indente les SSID sous « access-points: ».
    """
    base = nom.rsplit("/", 1)[-1]
    if "system-connections" in nom:
        m = RE_SSID_NM.search(txt)
        if not m:
            return []
        ssid = m.group(1)
        if re.fullmatch(r'(?:\d{1,3};)+', ssid):
            ssid = bytes(int(x) for x in ssid.split(";") if x).decode("utf-8", "replace")
        return [(ssid, "ssid= du profil NetworkManager")]
    if "network-scripts" in nom:
        return [(m.group(1), "ESSID= du fichier ifcfg") for m in RE_ESSID.finditer(txt)]
    if "wpa_supplicant" in nom and base.endswith(".conf"):
        return [(m.group(1), "ssid= de wpa_supplicant.conf") for m in RE_SSID_WPA.finditer(txt)]
    if "/iwd/" in nom and base.endswith((".psk", ".open", ".8021x")):
        ssid = base.rsplit(".", 1)[0]
        if ssid.startswith("="):
            try:
                ssid = bytes.fromhex(ssid[1:]).decode("utf-8", "replace")
            except ValueError:
                pass
        return [(ssid, "nom du fichier de profil iwd")]
    if "netplan" in nom and base.endswith((".yaml", ".yml")):
        return [(m.group(1).strip(), "clés sous access-points: de netplan")
                for bloc in RE_ACCESS_POINTS.split(txt)[1:]
                for m in RE_POINT_NETPLAN.finditer(bloc)]
    return []


def garde_sans_fil(nom):
    return ("system-connections" in nom or "network-scripts" in nom
            or "wpa_supplicant" in nom or "/iwd/" in nom or "netplan" in nom)
# ── fin commun ──

RE_PARE_FEU = re.compile(r'(firewalld|ufw|iptables|nftables)')
RE_NM_ID = re.compile(r'^\s*id\s*=\s*(.+?)\s*$', re.M)
RE_NM_UUID = re.compile(r'^\s*uuid\s*=\s*([0-9a-fA-F-]{36})', re.M)
RE_NM_PERM = re.compile(r'^\s*permissions\s*=\s*user:([^:;]+)', re.M)
RE_NM_DATE = re.compile(r'^([0-9a-fA-F-]{36})=(\d+)', re.M)


def _garde_reseau(nom):
    base = os.path.basename(nom)
    return (base in ("sshd_config", "ufw.conf", "timestamps") or garde_sans_fil(nom)
            or RE_PARE_FEU.search(nom) is not None)


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
    for nom, blob in c.membres_tar(t, _garde_reseau):
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
        elif garde_sans_fil(nom):
            # NetworkManager seul sait à quel compte un profil est réservé et
            # quand la machine s'y est associée pour la dernière fois
            idc, uuid, perm = RE_NM_ID.search(txt), RE_NM_UUID.search(txt), RE_NM_PERM.search(txt)
            ssids = ssids_de(nom, txt) or (
                [(idc.group(1), "id= du profil NetworkManager, sans ssid=")] if idc else [])
            for ssid, methode in ssids:
                reseaux.append({"ssid": ssid.strip(), "methode": methode,
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

# logins.json et « Login Data » portent les sites dont le compte a fait
# enregistrer le mot de passe : un compte tenu sur ce site, pas une visite de
# passage. Seuls les noms d'hôte en sont lus — jamais l'identifiant ni le secret.
BASES_NAVIGATEUR = ("places.sqlite", "History", "cookies.sqlite", "Cookies",
                    "Web Data", "Archived History", "Bookmarks", "formhistory.sqlite",
                    "logins.json", "Login Data")
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
# dpkg.log « 2026-01-04 18:30:00 », zypp « # 2026-01-05 21:10:00| », pacman
# « [2026-01-06T20:00:01+0100] » : la date en tête, quel que soit le décor
RE_DATE_LOG = re.compile(r'^[#\[\s]*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})')
# Le « \.? » de tête n'est pas décoratif : un domaine de cookie s'écrit avec un
# point devant (« .netflix.com », moz_cookies.host et Chrome cookies.host_key).
# Sans lui, le regard-arrière voit ce point, refuse la position, et TOUS les
# domaines de cookies sortent de l'analyse — l'artefact qui survit précisément
# au vidage de l'historique. Le regard-arrière reste, lui : il garantit qu'un
# hôte est pris entier (« www.exemple.fr », pas « exemple.fr » en plus).
RE_HOTE = re.compile(
    rb'(?<![a-z0-9.-])\.?(?:[a-z][a-z0-9+.-]{1,10}://)?(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}'
    rb'(?:[/?#][^\x00\s"\'<>]{0,120})?', re.I)


RE_SCHEMA = re.compile(r'^[a-z][a-z0-9+.-]{1,10}://', re.I)
RE_DEBUT_CHEMIN = re.compile(r'[/?#]')


def _fin_hote(hote):
    """Où s'arrête le nom d'hôte dans ce que RE_HOTE a capturé."""
    schema = RE_SCHEMA.match(hote)
    depart = schema.end() if schema else 0
    coupe = RE_DEBUT_CHEMIN.search(hote, depart)
    return coupe.start() if coupe else len(hote)


def _interesse(nom):
    base = os.path.basename(nom)
    return (base in BASES_NAVIGATEUR or base in FICHIERS_SECRETS
            or base.endswith(("_history", ".lesshst", ".pem", ".key"))
            or base.startswith("id_") or ".ssh/" in nom or ".gnupg/" in nom)


class Balayage:
    """Tous les motifs de domaine sur chaque base de navigateur, en un passage
    qui coûte peu.

    Appliquer vingt expressions à 50 Mo d'octets prend des minutes : le moteur
    essaie chaque alternative à chaque position. On ne le fait donc pas. Une
    seule expression simple extrait d'abord les NOMS D'HÔTE (avec leur schéma
    et le début du chemin) ; ils sont dédoublonnés et comptés — cent mille
    adresses uniques tiennent en quelques Mo — et les motifs ne courent que
    sur eux. Les pages libérées de la base y sont : on lit les octets, pas
    les tables.
    """

    def __init__(self, motifs):
        self.motifs = [(ident, re.compile(brut)) for ident, brut in motifs]

    def compter(self, blob):
        """{identifiant: {trouvé en minuscules: (occurrences, hôtes où il l'est)}}

        Le « trouvé » est le fragment que le motif de la règle a reconnu
        (« netflix. »), et l'hôte est la suite d'octets où il l'a été. On rend
        les deux : la règle se relit dans le premier, la pièce dans le second.
        Ces octets viennent d'une base lue au niveau des octets, pas en SQL :
        un hôte y arrive parfois collé à ce qui le suit. C'est visible, et
        c'est plus honnête que de le rogner au jugé.
        """
        par = collections.defaultdict(lambda: collections.defaultdict(
            lambda: [0, set()]))
        if not self.motifs:
            return par
        hotes = collections.Counter(m.group(0).lower().decode("latin-1")
                                    for m in RE_HOTE.finditer(blob))
        for hote, n in hotes.items():
            # Calculé PARESSEUSEMENT : il ne sert qu'en cas de correspondance,
            # cas très minoritaire, et il coûte 807 ns par hôte distinct — un
            # million d'hôtes, une seconde jetée. Mesuré : +17 % sur le balayage
            # quand il est calculé pour tous, +1 % ainsi.
            fin = None
            for ident, rx in self.motifs:
                for m in rx.finditer(hote):
                    if fin is None:
                        fin = _fin_hote(hote)
                    # La correspondance doit COMMENCER dans le nom d'hôte.
                    # RE_HOTE garde jusqu'à 120 caractères de chemin, et le
                    # motif d'une règle courait sur le tout : une page
                    # d'intranet professionnel nommée « netflix.etude-de-cas.pdf »
                    # sortait « domaine présent dans une base de navigateur »
                    # au nom de la règle « streaming au travail ». C'est une
                    # accusation, portée contre quelqu'un, sur un nom de
                    # fichier. Le chemin reste lu, car plusieurs règles
                    # livrées s'en servent exprès — « amazon\.[a-z]{2,3}/gp »
                    # distingue l'achat de la simple mention — mais elles
                    # ancrent toutes sur l'hôte, et c'est cet ancrage qu'on
                    # exige.
                    if m.start() >= fin:
                        continue
                    trouve = par[ident][m.group(0).lower()]
                    trouve[0] += n
                    trouve[1].add(hote[:80])
        return par


def lire_comptes(c, balayage):
    """Lit chaque archive de compte une fois. Rend un dict par compte :
    navigateurs [(source, comptes par motif)], historiques [(source, [(commande, date)])],
    secrets [(source, nom)], cles [(source, nom, chiffree)], autorisees [(source, clé, commentaire)]."""
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
    """[(commande, date)] d'un historique d'interpréteur.

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
            lignes.append((m.group(2), _epoch_iso(int(m.group(1)))))
            continue
        if l.strip():
            lignes.append((l, quand))
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
        for l in c.lignes(f):
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
                chemins.append((f"{courant}/{nom}" if courant else nom,
                                sys.intern(quand), sys.intern(ch[2])))
        inv[_compte_de(f, "inventaire.txt")] = (c.rel(f), chemins)
    return inv


def lire_paquets(c):
    """Ce qui est installé sur le POSTE. Rend [(source, methode, [(ligne, date)])].

    La liste des paquets ne dit pas qui les a posés : ces constats sont de
    portée « poste ». Les journaux d'installation, eux, portent une date —
    celle du poste, sans fuseau, telle que dpkg ou dnf l'écrivent.
    """
    out = []
    for f in c.chercher("_paquets.txt", "PAQUETS"):
        out.append((c.rel(f), METHODE_LISTE,
                    [(l, None) for l in c.lignes(f) if l.strip()]))
    for arch in c.chercher("_historique.tar.gz", "PAQUETS"):
        for nom, blob in c.membres_tar(arch, lambda n: not n.endswith((".sqlite", ".json"))
                                       or n.endswith("state.json")):
            txt = texte_de(nom, blob, f"{c.rel(arch)} → {nom}")
            if txt is None:
                continue
            lignes = []
            for l in txt.splitlines():
                if l.strip():
                    m = RE_DATE_LOG.match(l)
                    lignes.append((l, m.group(1) if m else None))
            if lignes:
                out.append((f"{c.rel(arch)} → {nom}",
                            "l'historique du gestionnaire de paquets", lignes))
    return out


def _grouper(lignes, motif):
    """Groupe les trouvailles d'un motif sur des (texte, date) :
    {trouvé en minuscules: (n, [(texte, date)] ≤ 5, [dates triées])}.

    Un dossier de films donne mille lignes pour un seul indice. Grouper rend le
    constat lisible et borné, sans perdre le compte, les exemples ni les dates.
    """
    par = {}
    for texte, date in lignes:
        for m in motif.finditer(texte):
            g = par.setdefault(m.group(0).lower(), [0, [], []])
            g[0] += 1
            if len(g[1]) < 5 and texte not in (x for x, _ in g[1]):
                g[1].append((texte, date))
            if date:
                g[2].append(date)
    return {k: (n, ex, sorted(dates)) for k, (n, ex, dates) in par.items()}


def _exemples(ex, large=100):
    return " ; ".join(f"{t.strip()[:large]} ({d})" if d else t.strip()[:large] for t, d in ex)


# ── 4 · les contrôles fixes sur ces pièces ───────────────────────────
SECRETS = [
    (re.compile(r'(?:^|\s)(?:-p|--password[= ])\S+'), "mot de passe sur la ligne de commande"),
    (re.compile(r'\b(?:PASSWORD|PASSWD|PASS|TOKEN|SECRET|API_?KEY)\s*=\s*\S{6,}', re.I),
     "identifiant affecté en clair"),
    (re.compile(r'curl\s+[^|]*-u\s+\S+:\S+'), "identifiant passé à curl"),
    (re.compile(r'\bmysql\s+.*-p\S+'), "mot de passe mysql sur la ligne de commande"),
    (re.compile(r'sshpass\s+-p'), "mot de passe SSH passé en argument"),
    # Bornes VOLONTAIREMENT plus larges que celles du skill forensic (AKIA+16,
    # gh?_+36, les longueurs exactes). Là-bas on balaie des gigaoctets d'octets
    # bruts, où une borne lâche noierait le rapport de faux positifs ; ici on
    # ne lit que des lignes de commande tapées par un humain, et un jeton
    # tronqué ou coupé au collage doit quand même se voir.
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
            for motif, quoi in SECRETS:
                for v, (n, ex, dates) in sorted(_grouper(lignes, motif).items()):
                    constat("secrets", quoi, ex[0][0].strip()[:140], source,
                            f"motif « {motif.pattern[:40]} » dans l'historique",
                            acteur=compte, date=dates[-1] if dates else None,
                            question="la charte interdit-elle de saisir un "
                                     "secret en argument de commande ?",
                            note=f"{n} saisie(s)" + ("" if dates else
                                 " — l'historique n'est pas daté : ne datez pas "
                                 "cette ligne sans autre source"))


def usage(c, pieces):
    """Ce qui a servi. Rien n'est qualifié : les familles rangent, la charte juge."""
    # Absente est conçue pour appliquer_regles(), qui la convertit en constat
    # « limite ». Ici elle était levée HORS de ce filet : sur un poste sans
    # profil de navigateur — un serveur, un poste verrouillé —, la toute
    # première famille la levait et emportait avec elle les supports amovibles
    # et les programmes posés dans un dossier personnel, qui n'ont pourtant
    # rien à voir. Mesuré : « usage 0 constats » contre 1 dès qu'un
    # places.sqlite VIDE était ajouté à la collecte.
    try:
        for famille, brut in FAMILLES:
            for t in _chercher_domaine(pieces, None, brut, famille):
                constat("usage", f"service {famille} présent dans un profil de navigateur",
                        t["valeur"], t["source"], t["methode"], acteur=t["acteur"],
                        date=t.get("date"),
                        question=f"la charte encadre-t-elle l'usage d'un service {famille} "
                                 "sur un poste professionnel ?", note=t["note"])
    except Absente as e:
        constat("limite", "familles de services non cherchées dans les navigateurs",
                str(e), c.prefix, "recherche par domaine dans les profils",
                portee="poste",
                note="l'absence de la pièce n'est pas l'absence d'usage")

    # Supports amovibles : le journal les porte, avec le compte dans le chemin.
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        # En FLUX, et non c.texte(j) : celui-ci décode la pièce entière et la
        # garde sous lru_cache jusqu'à la fin du processus — un pic de l'ordre
        # du gigaoctet sur un gros journal, pour une expression qui n'a besoin
        # que d'une ligne à la fois. Le motif est celui du skill forensic, au
        # caractère près : le point final de « Mounted /run/media/x/CLE. » ne
        # doit pas entrer dans l'étiquette, sans quoi les deux rapports
        # nomment le même support différemment.
        # Le crible littéral AVANT le motif, comme MOTIFS_JOURNAL en pose un
        # dans le skill forensic. « (?:/run)? » en tête interdit à re son
        # optimisation de préfixe, si bien que le motif balayait chaque ligne du
        # journal pour rien. Mesuré sur 2 000 000 de lignes : 5,55 s sans le
        # crible, 0,10 s avec — cinquante-cinq fois moins, pour un résultat
        # identique.
        vus = set()
        for ligne in c.lignes(j):
            if "/media/" in ligne:
                vus.update(RE_MEDIA.findall(ligne))
        for compte, etiquette in sorted(vus):
            constat("usage", "support amovible monté", etiquette,
                    c.rel(j), "chemins /run/media/<compte>/ dans le journal",
                    acteur=compte,
                    question="la charte encadre-t-elle l'usage de supports "
                             "amovibles, et exige-t-elle qu'ils soient chiffrés ?")

    for compte, (source, chemins) in sorted(pieces["inventaires"].items()):
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
QUESTION_PARTAGE = "la charte interdit-elle d'agir sous le compte d'un autre ?"


def _partage_fichiers(inventaires):
    for compte, (source, chemins) in sorted(inventaires.items()):
        autres = collections.defaultdict(list)
        for chemin, quand, prop in chemins:
            if prop not in (compte, "root"):
                autres[prop].append((chemin, quand))
        for prop, ex in sorted(autres.items()):
            constat("partage", "fichiers appartenant à un autre compte dans le "
                    "dossier personnel", f"{prop} : {len(ex)} fichier(s)", source,
                    "colonne propriétaire de ls -lRa, comparée au compte du dossier",
                    acteur=compte,
                    question="la charte interdit-elle l'usage du compte d'autrui, ou "
                             "le partage d'un poste de travail ?",
                    note="par exemple : " + _exemples(ex[:5]) + ". Un fichier créé "
                         "par un autre compte dans ce dossier suppose que ce compte "
                         "y a écrit — par une session à lui, ou par sudo")


def _partage_historiques(comptes_, locaux):
    for compte, p in sorted(comptes_.items()):
        for source, lignes in p["historiques"]:
            for v, (n, ex, dates) in sorted(_grouper(lignes, RE_PRISE_IDENTITE).items()):
                cible = next((g for g in RE_PRISE_IDENTITE.search(v).groups() if g), "")
                if cible.startswith("-") or cible not in locaux or cible == compte:
                    continue
                constat("partage", "prise de l'identité d'un autre compte local "
                        "depuis l'interpréteur", f"{compte} → {cible}", source,
                        "motif su / sudo -u / ssh compte@ dans l'historique",
                        acteur=compte, date=dates[-1] if dates else None,
                        question=QUESTION_PARTAGE,
                        note=f"{n} saisie(s), par exemple : " + _exemples(ex, 80)
                             + ("" if dates else ". Historique non daté"))


def _partage_cles(comptes_):
    """La même clé publique acceptée par deux comptes : une seule clé privée
    ouvre les deux."""
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


def _partage_sessions(pieces, locaux):
    """Un su vers un autre compte local ; deux ouvertures du même compte
    depuis deux origines à moins de dix minutes — deux personnes, ou une seule
    et deux machines : à vérifier."""
    for f in pieces["faits"]:
        if f.get("categorie") == "evenement" and f.get("fait") == "changement d'utilisateur (su)":
            cible = f.get("cible") or (re.search(r'est devenu (\S+)', f.get("note") or "") or [None, None])[1]
            if cible in locaux and cible != f.get("acteur"):
                constat("partage", "prise de l'identité d'un autre compte local (su)",
                        f"{f.get('acteur')} → {cible}", "faits.jsonl (skill forensic-linux)",
                        f"fait {f['id']} : ligne « session opened for user » du journal",
                        acteur=f.get("acteur"), date=f.get("horodatage"),
                        question=QUESTION_PARTAGE)
    par_compte = collections.defaultdict(list)
    for f, q in pieces["ouvertures"]:
        origine = f.get("origine") or (re.search(r'depuis ([^\s,]+)', f.get("note") or "")
                                       or [None, "console"])[1]
        par_compte[f["acteur"]].append((q, origine, f["id"]))
    for compte, liste in sorted(par_compte.items()):
        liste.sort()
        for (q1, o1, i1), (q2, o2, i2) in zip(liste, liste[1:]):
            if o1 != o2 and (q2 - q1).total_seconds() < 600:
                constat("partage", "deux ouvertures du même compte depuis deux "
                        "origines à moins de dix minutes", f"{o1} puis {o2}",
                        "faits.jsonl (skill forensic-linux)",
                        f"faits {i1} et {i2}, horodatages comparés", acteur=compte,
                        date=q2.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                        question="la charte interdit-elle de prêter son compte ?",
                        note="deux personnes, ou une seule avec deux machines : la "
                             "collecte ne tranche pas. Croiser avec les adresses "
                             "attribuées à chaque poste")


def partage(pieces, locaux):
    _partage_fichiers(pieces["inventaires"])
    _partage_historiques(pieces["comptes"], locaux)
    _partage_cles(pieces["comptes"])
    _partage_sessions(pieces, locaux)


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
    "programme": "ce que dit la pièce citée — la liste des paquets établit la "
                 "PRÉSENCE, l'historique du gestionnaire seulement qu'une pose "
                 "ou un RETRAIT a eu lieu ; ni l'une ni l'autre ne dit que le "
                 "programme a servi",
    "fichier": "la PRÉSENCE d'un fichier dans le dossier du compte, pas qui "
               "l'y a mis ni ce qu'il contient",
    "commande": "qu'une commande a été SAISIE dans l'interpréteur de ce compte "
                "— datée seulement si l'historique l'est",
    "wifi": "que la machine s'est ASSOCIÉE au moins une fois à ce réseau — "
            "donc qu'elle est sortie du site",
    "horaire": "qu'une session a été OUVERTE hors des heures indiquées, pas "
               "qu'un travail y a été fait",
    "chaine": "que la chaîne FIGURE dans la pièce citée — pas ce qu'elle y faisait",
}

JOURS = ("lun", "mar", "mer", "jeu", "ven", "sam", "dim")
RE_PLAGE = re.compile(
    r'^(%s)\s*-\s*(%s)\s+(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$'
    % ("|".join(JOURS), "|".join(JOURS)), re.I)


class Absente(Exception):
    """La pièce qu'un chercheur voulait n'est pas dans la collecte."""


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
                    motif = valeur.lower()
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


# Les chercheurs : un par type d'indice. Chacun rend des dicts prêts pour le
# constat — quoi, valeur, source, methode, et acteur/portee/date/note — et lève
# Absente quand la pièce qu'il lui faut n'est pas là.
def _chercher_domaine(pieces, motif, brut, ident):
    """ident : ce que Balayage a compté sous ce nom — (règle, motif) ou famille."""
    comptes_ = pieces["comptes"]
    if not any(p["navigateurs"] for p in comptes_.values()):
        raise Absente("aucune base de navigateur dans la collecte")
    faits, visites = pieces["faits"], pieces["visites"]
    for compte, p in sorted(comptes_.items()):
        for source, comptages in p["navigateurs"]:
            for v, (n, hotes) in sorted(comptages.get(ident, {}).items()):
                date = None
                note = (f"{n} occurrence(s) dans la base, dans "
                        + ", ".join("« %s »" % h for h in sorted(hotes)[:4]))
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
                             "cookies, d'un favori, d'un mot de passe enregistré "
                             "ou d'une page libérée — pas d'une visite datée. "
                             "Le fichier nommé en source dit lequel")
                else:
                    note += " ; la date se lit avec --faits"
                yield dict(quoi="domaine présent dans une base de navigateur",
                           valeur=v, source=source, acteur=compte, date=date,
                           methode=f"motif « {brut} » cherché dans les noms d'hôte "
                                   "extraits des octets de la base, sans l'ouvrir en SQL",
                           note=note)


def _chercher_inventaire(pieces, motif, brut, ident, quoi):
    if not pieces["inventaires"]:
        raise Absente("aucun inventaire de dossier personnel")
    for compte, (source, chemins) in sorted(pieces["inventaires"].items()):
        for v, (n, ex, _) in sorted(_grouper(((ch, q) for ch, q, _ in chemins), motif).items()):
            yield dict(quoi=quoi, valeur=v, source=source, acteur=compte,
                       methode=f"motif « {brut} » cherché dans les chemins de "
                               "l'inventaire (ls -lRa)",
                       note=f"{n} chemin(s), par exemple : " + _exemples(ex, 200)
                            + ". La date entre parenthèses est celle que ls "
                            "affiche : modification, sans année si récente")


# « apt remove », « dnf erase », « pacman -R », « Remove: paquet:amd64 » : une
# ligne d'historique qui dit le CONTRAIRE d'une installation.
RE_RETRAIT = re.compile(r'(?:\b(?:remove|purge|erase|uninstall|autoremove)\b'
                        r'|\bpacman\b[^\n]*\s-[A-Za-z]*R)', re.I)
METHODE_LISTE = "la liste des paquets installés"


def _chercher_programme(pieces, motif, brut, ident):
    if not pieces["paquets"] and not pieces["inventaires"]:
        raise Absente("ni liste de paquets ni inventaire")
    for source, methode, lignes in pieces["paquets"]:
        installee = methode == METHODE_LISTE
        for v, (n, ex, dates) in sorted(_grouper(lignes, motif).items()):
            ligne = ex[0][0].strip()[:120]
            if installee:
                quoi = "programme installé sur le poste"
                note = ("la liste des paquets ne dit pas quel compte a demandé "
                        "l'installation : la portée est le poste. Ligne : " + ligne)
            else:
                # L'historique garde la trace des poses ET des retraits. Le
                # constat annonçait « programme installé sur le poste » pour une
                # ligne « Commandline: apt remove teamviewer », alors que la
                # liste des paquets installés, elle, ne le portait plus : le
                # rapport accusait quelqu'un d'avoir un logiciel interdit en
                # citant la ligne qui prouve qu'il l'a RETIRÉ.
                retrait = bool(RE_RETRAIT.search(ligne))
                quoi = ("programme RETIRÉ, d'après l'historique du gestionnaire"
                        if retrait else
                        "programme posé, d'après l'historique du gestionnaire")
                note = ("l'historique dit ce qui a été FAIT, pas ce qui est là "
                        "aujourd'hui : c'est la liste des paquets installés qui "
                        "en décide" + (" — et cette ligne-ci est un RETRAIT"
                                       if retrait else "") + ". Ligne : " + ligne)
            yield dict(quoi=quoi, valeur=v, source=source,
                       portee="poste", date=dates[-1] if dates else None,
                       methode=f"motif « {brut} » cherché dans {methode}",
                       note=note)
    if pieces["inventaires"]:
        yield from _chercher_inventaire(pieces, motif, brut, ident,
                                        "programme présent dans le dossier personnel")


def _chercher_commande(pieces, motif, brut, ident):
    comptes_ = pieces["comptes"]
    if not any(p["historiques"] for p in comptes_.values()):
        raise Absente("aucun historique d'interpréteur")
    for compte, p in sorted(comptes_.items()):
        for source, lignes in p["historiques"]:
            for v, (n, ex, dates) in sorted(_grouper(lignes, motif).items()):
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
                           note=note + ". Par exemple : " + _exemples(ex))


def _chercher_wifi(pieces, motif, brut, ident):
    if not pieces["reseaux"]:
        raise Absente("aucun profil de connexion réseau")
    for o in pieces["reseaux"]:
        if not motif.search(" ".join(x for x in (o["ssid"], o["id"]) if x)):
            continue
        yield dict(quoi="réseau sans fil enregistré sur le poste", valeur=o["ssid"],
                   source=o["source"], acteur=o["acteur"], date=o["vu_le"],
                   portee="compte" if o["acteur"] else "poste",
                   methode=f"motif « {brut} » cherché dans le SSID ({o['methode']})",
                   note="date de la dernière association, lue dans "
                        "var/lib/NetworkManager/timestamps" if o["vu_le"] else
                        "aucune date : seul NetworkManager date l'association, et "
                        "son fichier « timestamps » manque ou ne connaît pas ce profil")


def _chercher_horaire(pieces, motif, brut, ident):
    """Les ouvertures de session hors des heures ouvrées, groupées par journée.

    C'est le seul endroit où le fuseau compte AVANT le rapport : dire qu'une
    session est « hors heures » suppose de lire l'heure dans le fuseau du poste.
    """
    if not pieces["faits"]:
        raise Absente("les heures demandent --faits (faits.jsonl du skill forensic-linux)")
    if not pieces["ouvertures"]:
        raise Absente("aucune ouverture de session datée dans faits.jsonl")
    jours, deb, fin = motif
    par = {}
    for f, q in pieces["ouvertures"]:
        if q.weekday() in jours and deb <= q.hour * 60 + q.minute < fin:
            continue
        par.setdefault((f.get("acteur") or "?", q.date().isoformat()), []).append((q, f["id"]))
    nom_fuseau = str(pieces["fuseau"]) if pieces["fuseau"] else "UTC, faute de fuseau connu"
    for (qui, jour), heures in sorted(par.items()):
        heures.sort()
        yield dict(quoi="session ouverte hors des heures indiquées",
                   valeur=f"{jour} ({JOURS[heures[0][0].weekday()]}) : "
                          + ", ".join(q.strftime("%H:%M") for q, _ in heures),
                   source="faits.jsonl (skill forensic-linux)",
                   acteur=None if qui == "?" else qui,
                   date=heures[0][0].astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                   methode=f"heures ouvrées « {brut} » comparées à l'horodatage des "
                           f"ouvertures de session, lues dans le fuseau {nom_fuseau}",
                   note=f"{len(heures)} ouverture(s) : " + ", ".join(i for _, i in heures))


def _chercher_texte(pieces, motif, brut, ident):
    """Une chaîne ou une expression, dans toutes les pièces texte : historiques
    et inventaires des comptes, paquets, journal du poste."""
    if not pieces["textes"]:
        raise Absente("aucune pièce texte dans la collecte")
    for source, acteur, lignes in pieces["textes"]:
        for v, (n, ex, dates) in sorted(_grouper(lignes(), motif).items()):
            yield dict(quoi="texte présent dans une pièce", valeur=v, source=source,
                       acteur=acteur, date=dates[-1] if dates else None,
                       portee="compte" if acteur else "poste",
                       methode=f"motif « {brut} » cherché ligne à ligne",
                       note=f"{n} ligne(s), par exemple : " + _exemples(ex))


CHERCHEURS = {
    "domaine": _chercher_domaine, "programme": _chercher_programme,
    "fichier": functools.partial(_chercher_inventaire,
                                 quoi="fichier présent dans le dossier personnel"),
    "commande": _chercher_commande, "wifi": _chercher_wifi,
    "horaire": _chercher_horaire, "chaine": _chercher_texte,
}


def _adosser(r, theme_et_debut):
    """« controle: partage » : la règle s'adosse à un contrôle fixe. Ses
    constats déjà posés reçoivent le numéro — sans rien perdre : un constat
    peut porter plusieurs règles, et sa question d'origine reste."""
    theme, _, debut = theme_et_debut.partition("/")
    n = 0
    for x in CONSTATS:
        if x["theme"] == theme and x["constat"].lower().startswith(debut):
            x.setdefault("regle", r["regle"])
            x.setdefault("regles", []).append(r["regle"])
            x["note"] = ((x.get("note") + ". ") if x.get("note") else "") + \
                f"règle {r['regle']} « {r['titre']} » : ce contrôle traduit-il fidèlement " \
                "ce que dit la règle ?"
            n += 1
    return n


def appliquer_regles(c, regles, pieces):
    """Cherche dans la collecte les indices que les règles désignent.

    Deux silences qui ne se confondent pas : la pièce manquait — « limite »,
    la règle n'a pas été vérifiée — ou elle était là et n'a rien donné —
    « conforme », en disant que cela ne prouve pas le respect de la règle.
    """
    for r in regles:
        poses, absentes, deja = 0, [], set()
        if not r["indices"]:
            # Une règle SANS indice n'a jamais été cherchée : la dire
            # « conforme » est un acquittement prononcé sans instruction. Le
            # cas se présente dès qu'on recopie une phrase de la charte en
            # remettant sa traduction à plus tard — et « conforme » est
            # justement ce que le décompte des manquements écarte.
            constat("limite", f"règle {r['regle']} : aucun indice à chercher",
                    r["titre"], c.prefix, "lecture du fichier de règles",
                    regle=r["regle"],
                    note="cette règle n'a pas été traduite en quelque chose que "
                         "l'on cherche dans la collecte : elle n'a donc PAS été "
                         "vérifiée. Ajoutez-lui un indice, ou retirez-la du "
                         "fichier de règles")
            continue
        for cle, motif, etiquette, brut in r["indices"]:
            if cle == "controle":
                poses += _adosser(r, motif)
                continue
            try:
                trouves = list(CHERCHEURS[cle](pieces, motif, brut, (r["regle"], brut)))
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


def _pieces_texte(c, pieces):
    """[(source, acteur, lignes)] : tout ce qui se lit ligne à ligne. `lignes`
    est une fonction : le journal du poste peut faire 200 Mo, il se relit
    plutôt que de se garder."""
    textes = []
    for compte, p in sorted(pieces["comptes"].items()):
        for source, lignes in p["historiques"]:
            textes.append((source, compte, lambda l=lignes: l))
    for compte, (source, chemins) in sorted(pieces["inventaires"].items()):
        textes.append((source, compte, lambda ch=chemins: ((x, q) for x, q, _ in ch)))
    for source, _, lignes in pieces["paquets"]:
        textes.append((source, None, lambda l=lignes: l))
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        textes.append((c.rel(j), None, lambda: ((l, None) for l in c.lignes(j))))
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


def _ouvertures(faits, fuseau):
    """[(fait, instant)] des ouvertures de session datées, dans le fuseau du poste."""
    out = []
    for f in faits:
        if f.get("categorie") == "evenement" and "ouverture de session" in f.get("fait", "") \
                and f.get("acteur"):
            q = instant(f.get("horodatage"), fuseau)
            if q:
                out.append((f, q))
    return out


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


def etape(nom, fn, *args, defaut=None):
    """Une étape : ce qu'elle rend, combien de constats elle a posés, et une
    erreur qui ne fait pas tomber les autres."""
    avant = len(CONSTATS)
    try:
        resultat = fn(*args)
    except Exception as e:                                        # noqa: BLE001
        print(f"  ! {nom} : {type(e).__name__} {e}", file=sys.stderr)
        resultat = defaut
    print(f"  {nom:26s} {len(CONSTATS) - avant:4d} constats", file=sys.stderr)
    return resultat


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
    fuseau = _fuseau(args.fuseau, faits)

    # tous les motifs de domaine — familles fixes et règles — en un balayage
    motifs = list(FAMILLES) + [((r["regle"], brut), brut) for r in regles
                               for cle, _, _, brut in r["indices"] if cle == "domaine"]
    pieces = {"faits": faits, "fuseau": fuseau,
              "visites": _visites_par_compte(faits),
              "ouvertures": _ouvertures(faits, fuseau)}
    pieces["comptes"] = etape("lecture des comptes", lire_comptes, c, Balayage(motifs), defaut={})
    pieces["inventaires"] = etape("inventaires", lire_inventaires, c, defaut={})
    pieces["paquets"] = etape("paquets", lire_paquets, c, defaut=[])
    pieces["reseaux"] = etape("réseau et durcissement", reseau, c, defaut=[])
    pieces["textes"] = _pieces_texte(c, pieces) if any(
        cle == "chaine" for r in regles for cle, _, _, _ in r["indices"]) else []

    locaux = etape("comptes et mots de passe", comptes, c, defaut=set())
    etape("secrets", secrets, pieces["comptes"])
    etape("usage", usage, c, pieces)
    etape("partage de compte", partage, pieces, locaux)
    if regles:
        etape(f"règles fournies ({len(regles)})", appliquer_regles, c, regles, pieces)

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
            rid for x in CONSTATS if x["theme"] not in ("limite", "conforme")
            for rid in x.get("regles", [x["regle"]] if x.get("regle") else []))
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
