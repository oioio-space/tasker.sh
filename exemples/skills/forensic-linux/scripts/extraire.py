#!/usr/bin/env python3
"""Extrait des FAITS datés et sourcés d'une collecte tasker.sh collecte-linux.

    extraire.py <dossier de collecte> [-o faits.jsonl]

Chaque fait porte d'où il vient et comment il a été obtenu : un lecteur doit
pouvoir refaire le geste à la main. Rien n'est interprété ici — le tri, le
recoupement et le jugement sont le travail du rapport.

Bibliothèque standard seulement. La collecte n'est jamais modifiée : les
archives sont lues en flux, jamais dépaquetées sur place.
"""
import argparse, bz2, gzip, hashlib, io, json, lzma, os, re, sqlite3, sys, tarfile, tempfile
import struct
from datetime import datetime, timezone

FAITS = []
_N = [0]


def fait(categorie, quoi, valeur, source, methode, horodatage=None, acteur=None,
         confiance="certaine", note=None):
    """Pose un fait. source = chemin dans la collecte ; methode = le geste."""
    _N[0] += 1
    f = {"id": f"F{_N[0]:04d}", "categorie": categorie, "fait": quoi,
         "valeur": valeur, "source": source, "methode": methode}
    for k, v in (("horodatage", horodatage), ("acteur", acteur),
                 ("confiance", confiance), ("note", note)):
        if v is not None:
            f[k] = v
    FAITS.append(f)
    return f


def _compte_de(chemin, suffixe):
    """PREFIX_<compte>_<suffixe> → compte."""
    m = re.search(rf'_([^_]+)_{re.escape(suffixe)}$', os.path.basename(chemin))
    return m.group(1) if m else "?"


# ── accès à la collecte ───────────────────────────────────────────────
class Collecte:
    """Le dossier PREFIX/ produit par collecte-linux."""

    def __init__(self, racine):
        self.racine = os.path.abspath(racine)
        self.prefix = os.path.basename(self.racine)
        self.lus = set()          # ce qui a servi, pour le manifeste
        if not os.path.isdir(self.racine):
            sys.exit(f"pas un dossier : {self.racine}")

    def rel(self, chemin):
        return os.path.relpath(chemin, self.racine)

    def chercher(self, motif, sous=None):
        """Chemins absolus des fichiers dont le nom contient motif."""
        base = os.path.join(self.racine, sous) if sous else self.racine
        trouves = []
        for d, _, fichiers in os.walk(base):
            for n in fichiers:
                if motif in n:
                    trouves.append(os.path.join(d, n))
        return sorted(trouves)

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

    def dates_tar(self, archive):
        """La date de chaque membre. tar la conserve : c'est souvent la seule
        façon de dater une pièce dont le contenu n'est pas horodaté."""
        dates = {}
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m in t:
                    if m.isfile():
                        nom = m.name[2:] if m.name.startswith("./") else m.name
                        dates[nom] = m.mtime
        except (tarfile.TarError, OSError, EOFError):
            pass
        return dates

    def membres_tar(self, archive):
        """(nom, contenu binaire) de chaque fichier régulier d'un .tar.gz."""
        self.lus.add(archive)
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m in t:
                    if not m.isfile():
                        continue
                    fh = t.extractfile(m)
                    if fh is None:
                        continue
                    # lstrip("./") mangerait le point d'un fichier caché :
                    # « ./.viminfo » deviendrait « viminfo ».
                    nom = m.name[2:] if m.name.startswith("./") else m.name
                    yield nom, fh.read()
        except (tarfile.TarError, OSError, EOFError) as e:
            print(f"  ! archive illisible {os.path.basename(archive)} : {e}",
                  file=sys.stderr)


# Les dates de « last » et de « rpm --last » sortent dans la langue du poste
# COLLECTEUR — « lun. sept.  2 » sur un poste français. strptime, lui, lit
# dans la langue du poste ANALYSTE : deux machines réglées autrement ne
# tireraient pas les mêmes faits de la même collecte. On lit donc les dates
# soi-même, sans locale : c'est ce qui rend l'extraction reproductible.
_ACCENTS = str.maketrans("àâäéèêëîïôöùûüçÀÂÄÉÈÊËÎÏÔÖÙÛÜÇ",
                         "aaaeeeeiioouuucAAAEEEEIIOOUUUC")


def _plier(mot):
    """Minuscules, sans accent ni point : « Août. » devient « aout »."""
    return mot.translate(_ACCENTS).lower().strip(".").strip()


MOIS_NOMS = {}
for _i, _noms in enumerate(
        [("janvier", "january"), ("fevrier", "february"), ("mars", "march"),
         ("avril", "april"), ("mai", "may"), ("juin", "june"),
         ("juillet", "july"), ("aout", "august"), ("septembre", "september"),
         ("octobre", "october"), ("novembre", "november"),
         ("decembre", "december")], 1):
    for _n in _noms:
        for _forme in (_n, _n[:4], _n[:3]):
            MOIS_NOMS.setdefault(_forme, _i)

RE_HMS = re.compile(r'\b(\d{1,2}):(\d{2}):(\d{2})\b')
_MOT = r"[^\W\d_]{2,10}\.?"
# « lun. sept.  2 11:44:03 2019 » — la date de last -F, toutes langues
RE_BLOC_LAST = re.compile(rf'({_MOT}\s+{_MOT}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\s+\d{{4}})')
# « mar. 27 août 2019 17:19:45 » — celle de rpm -qa --last
RE_BLOC_RPM = re.compile(rf'({_MOT}\s+\d{{1,2}}\s+{_MOT}\s+\d{{4}}\s+\d{{2}}:\d{{2}}:\d{{2}})')


def lire_date(blob):
    """Une date écrite dans n'importe quelle langue, en ISO. None si illisible.

    Le jour de la semaine n'est pas reconnu : il vient toujours en tête, dans
    « last » comme dans « rpm --last », donc on l'écarte — le mois est le mot
    qui reste. Cela évite d'avoir à distinguer « mar. » (mardi) de « mars ».
    """
    if not blob:
        return None
    hms = RE_HMS.search(blob)
    an = re.search(r'\b(\d{4})\b', blob)
    if not (hms and an):
        return None
    mots = re.findall(r'[^\W\d_]+', blob)
    mois = None
    for mot in (mots[1:] if len(mots) > 1 else mots):
        mois = MOIS_NOMS.get(_plier(mot))
        if mois:
            break
    if not mois:
        return None
    # Les nombres de 1 à 31 hors heure : le premier restant est le quantième.
    heure = [int(hms.group(i)) for i in (1, 2, 3)]
    reste = blob.replace(hms.group(0), " ", 1).replace(an.group(1), " ", 1)
    jours = [int(j) for j in re.findall(r'\b(\d{1,2})\b', reste) if 1 <= int(j) <= 31]
    if not jours:
        return None
    try:
        return datetime(int(an.group(1)), mois, jours[0], *heure).isoformat()
    except ValueError:
        return None


def lire_ligne_last(ligne):
    """« qui tty depuis <date> - <date> (durée) », dans n'importe quelle langue."""
    blocs = RE_BLOC_LAST.findall(ligne)
    if not blocs:
        return None
    tete = ligne[:ligne.index(blocs[0])].split()
    if not tete:
        return None
    duree = re.search(r'\(([^)]*)\)\s*$', ligne)
    return {"qui": tete[0],
            "tty": tete[1] if len(tete) > 1 else "",
            "ou": tete[2] if len(tete) > 2 else "",
            "debut": blocs[0],
            "fin": blocs[1] if len(blocs) > 1 else None,
            "duree": duree.group(1) if duree else None}


# ── 1 · la machine ────────────────────────────────────────────────────
def machine(c):
    h = c.un("hostname", "SYSTEME")
    if h:
        nom = c.texte(h).strip()
        if nom:
            fait("machine", "nom de la machine", nom, c.rel(h), "cat")

    osr = c.un("os-release", "SYSTEME")
    if osr:
        champs = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', c.texte(osr), re.M))
        for cle, quoi in (("PRETTY_NAME", "système installé"),
                          ("VERSION_ID", "version du système"),
                          ("ID", "famille du système")):
            if champs.get(cle):
                fait("machine", quoi, champs[cle], c.rel(osr),
                     f"grep {cle}= os-release")

    tz = c.un("_localtime.txt", "SYSTEME")
    if tz:
        v = c.texte(tz).strip()
        if v:
            fait("machine", "fuseau horaire du poste", v, c.rel(tz),
                 "readlink /etc/localtime (ou la règle TZ du fichier)",
                 note="les dates des journaux locaux se lisent dans ce fuseau")

    inst = c.un("_installation.tar.gz", "SYSTEME")
    if inst:
        for nom, blob in c.membres_tar(inst):
            if nom.endswith("machine-id"):
                fait("machine", "machine-id", blob.decode("utf-8", "replace").strip(),
                     f"{c.rel(inst)} → {nom}", "tar -xO",
                     note="nomme aussi le dossier du journal systemd")
            elif nom.endswith("adjtime"):
                lignes = blob.decode("utf-8", "replace").split()
                mode = "UTC" if "UTC" in lignes else ("heure locale" if "LOCAL" in lignes else "?")
                fait("machine", "horloge matérielle", mode, f"{c.rel(inst)} → {nom}",
                     "tar -xO etc/adjtime",
                     note="en heure locale, les dates du BIOS et des journaux divergent")
            elif nom.endswith("machine-info"):
                champs = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$',
                                         blob.decode("utf-8", "replace"), re.M))
                for cle, quoi in (("PRETTY_HOSTNAME", "nom affiché de la machine"),
                                  ("CHASSIS", "type de châssis"),
                                  ("DEPLOYMENT", "environnement déclaré")):
                    if champs.get(cle):
                        fait("machine", quoi, champs[cle], f"{c.rel(inst)} → {nom}",
                             f"grep {cle}= etc/machine-info")
            elif nom.endswith("crypttab"):
                for l in blob.decode("utf-8", "replace").splitlines():
                    if l.strip() and not l.startswith("#"):
                        fait("machine", "volume chiffré déclaré", l.split()[0],
                             f"{c.rel(inst)} → {nom}", "cat etc/crypttab",
                             note="la machine montait un volume chiffré au démarrage")
        # tar garde la date de chaque pièce : elle date ce que le contenu ne
        # date pas. Le journal de l'installateur donne ainsi la pose du système,
        # et l'horloge de systemd-timesync la dernière synchronisation.
        for nom, quand in sorted(c.dates_tar(inst).items()):
            iso = (datetime.fromtimestamp(quand, timezone.utc).isoformat()
                   .replace("+00:00", "Z")) if quand else None
            if "anaconda" in nom or "installer" in nom or nom.endswith("-ks.cfg"):
                fait("machine", "installation du système (journal de l'installateur)",
                     nom, f"{c.rel(inst)} → {nom}", "date du membre dans l'archive tar",
                     horodatage=iso, confiance="forte",
                     note="la date la plus sûre pour la pose du système")
            elif nom.endswith("timesync/clock"):
                fait("machine", "dernière synchronisation de l'horloge", nom,
                     f"{c.rel(inst)} → {nom}", "date du membre dans l'archive tar",
                     horodatage=iso,
                     note="systemd-timesync touche ce fichier à chaque accord : "
                          "au-delà, les dates de la machine sont moins sûres")

    # La plus vieille salve de paquets date l'installation.
    pk = c.un("_paquets.txt", "PAQUETS")
    if pk:
        lignes = [l for l in c.texte(pk).splitlines() if l.strip()]
        dates = []
        for l in lignes:
            m = RE_BLOC_RPM.search(l)
            if m:
                dates.append((m.group(1), l.split()[0]))
        if dates:
            vieux, paquet = dates[-1]
            iso = lire_date(vieux)
            fait("machine", "installation du système (plus ancien paquet posé)",
                 paquet, c.rel(pk), "rpm -qa --last | tail -n 1",
                 horodatage=iso or vieux, confiance="forte",
                 note="date de la salve d'installation, pas une preuve directe")
            recent, paquet_r = dates[0]
            fait("machine", "dernier paquet installé", paquet_r, c.rel(pk),
                 "rpm -qa --last | head -n 1",
                 horodatage=lire_date(recent) or recent,
                 note="borne basse de la dernière utilisation administrative")
        # dpkg-query -l pose cinq lignes d'en-tête avant la liste : seules
        # celles qui commencent par un état à deux lettres sont des paquets.
        dpkg = [l for l in lignes if re.match(r'^[a-zA-Z]{2}\s+\S', l)]
        if dpkg and not dates:
            fait("machine", "paquets installés (nombre)", str(len(dpkg)), c.rel(pk),
                 "compte des lignes d'état de dpkg-query -l",
                 note="dpkg ne date pas les installations : voir le journal "
                      "du gestionnaire pour les dates")
        else:
            fait("machine", "paquets installés (nombre)", str(len(lignes)), c.rel(pk),
                 "wc -l")


# ── 2 · comptes et domaine ────────────────────────────────────────────
def comptes(c):
    p = c.un("passwd", "COMPTES")
    humains = []
    if p:
        for l in c.texte(p).splitlines():
            ch = l.split(":")
            if len(ch) < 7:
                continue
            nom, uid, home, shell = ch[0], ch[2], ch[5], ch[6]
            try:
                uid_n = int(uid)
            except ValueError:
                continue
            interactif = not shell.endswith(("nologin", "false"))
            if uid_n >= 1000 and interactif:
                humains.append(nom)
                fait("compte", "compte local ouvrant une session", nom, c.rel(p),
                     "cut -d: -f1,3,6,7 /etc/passwd",
                     acteur=nom, note=f"uid {uid}, dossier {home}, shell {shell}")
            elif interactif and uid_n < 1000 and nom != "root":
                fait("compte", "compte de service avec un shell", nom, c.rel(p),
                     "cut -d: -f1,3,7 /etc/passwd", acteur=nom,
                     confiance="forte", note=f"uid {uid}, shell {shell} — inhabituel")
        fait("compte", "comptes locaux ouvrant une session (nombre)",
             str(len(humains)), c.rel(p), "wc -l sur les uid >= 1000")

    dom = c.un("_domaine.tar.gz", "COMPTES")
    if dom:
        vus = set()
        for nom, blob in c.membres_tar(dom):
            txt = blob.decode("utf-8", "replace", ) if len(blob) < 4_000_000 else ""
            if nom.endswith("sssd.conf"):
                for d in re.findall(r'^\s*domains?\s*=\s*(.+)$', txt, re.M | re.I):
                    fait("domaine", "domaine déclaré (sssd)", d.strip(),
                         f"{c.rel(dom)} → {nom}", "grep '^domains' sssd.conf")
                for s in re.findall(r'^\s*ad_server\s*=\s*(.+)$', txt, re.M | re.I):
                    fait("domaine", "contrôleur de domaine déclaré", s.strip(),
                         f"{c.rel(dom)} → {nom}", "grep ad_server sssd.conf")
                for s in re.findall(r'^\s*ldap_uri\s*=\s*(.+)$', txt, re.M | re.I):
                    fait("domaine", "annuaire LDAP déclaré", s.strip(),
                         f"{c.rel(dom)} → {nom}", "grep ldap_uri sssd.conf")
            elif nom.endswith("krb5.conf") or "krb5.conf.d" in nom:
                for r in re.findall(r'^\s*default_realm\s*=\s*(.+)$', txt, re.M):
                    fait("domaine", "royaume Kerberos", r.strip(),
                         f"{c.rel(dom)} → {nom}", "grep default_realm krb5.conf")
                for kdc in re.findall(r'^\s*kdc\s*=\s*(.+)$', txt, re.M):
                    fait("domaine", "KDC (contrôleur de domaine)", kdc.strip(),
                         f"{c.rel(dom)} → {nom}", "grep kdc krb5.conf")
            elif nom.endswith("smb.conf"):
                for w in re.findall(r'^\s*workgroup\s*=\s*(.+)$', txt, re.M | re.I):
                    fait("domaine", "groupe de travail SMB", w.strip(),
                         f"{c.rel(dom)} → {nom}", "grep workgroup smb.conf")
            elif nom.endswith("krb5.keytab"):
                fait("domaine", "keytab Kerberos présent", nom,
                     f"{c.rel(dom)} → {nom}", "tar -t",
                     note="la machine était bien jointe au domaine")
            # Le cache sss nomme les comptes du domaine réellement vus ici.
            if "/sss/db/" in nom or nom.endswith(".ldb"):
                for u in set(re.findall(rb'name=([A-Za-z0-9._-]{2,32}),cn=users', blob)):
                    vus.add(u.decode())
        for u in sorted(vus):
            fait("compte", "compte de domaine vu sur la machine", u,
                 f"{c.rel(dom)} → var/lib/sss/db", "strings sur le cache sss",
                 acteur=u, confiance="forte",
                 note="présent dans le cache : ce compte s'est connecté ou a été résolu ici")


# ── 3 · sessions, démarrages, arrêts ──────────────────────────────────


def _last(c, chemin, categorie, quoi, methode):
    """Rend le nombre de lignes retenues : zéro appelle le lecteur binaire."""
    if not chemin:
        return 0
    poses = 0
    for ligne in c.texte(chemin).splitlines():
        if not ligne.strip() or ligne.startswith(("wtmp begins", "btmp begins")):
            continue
        g = lire_ligne_last(ligne)
        if not g:
            continue
        iso = lire_date(g["debut"])
        depuis = g["ou"] or ""
        acteur = g["qui"]
        note = f"tty {g['tty']}"
        if depuis and depuis not in ("-", ":0"):
            note += f", depuis {depuis}"
        if g.get("duree"):
            note += f", durée {g['duree']}"
        if g.get("fin"):
            note += f", fin {lire_date(g['fin']) or g['fin']}"
        fait(categorie, quoi, acteur, c.rel(chemin), methode,
             horodatage=iso or g["debut"], acteur=acteur, note=note)
        poses += 1
    return poses


def _utmp_brut(c, nom_fichier, categorie, quoi_defaut):
    """Lit le wtmp ou le btmp COPIÉ, quand aucune sortie texte n'existe.

    La collecte fait tourner « last » quand il est là ; si l'image n'avait pas
    de wtmp, ou si l'outil manquait, seul le binaire est arrivé. Le lire ici
    rend l'analyse indépendante de ce qui tournait au moment de la collecte —
    et donne des dates en epoch, donc sans locale ni année à deviner.
    """
    dossier = os.path.join(c.racine, "CONNEXIONS")
    # wtmp, wtmp.1, wtmp-20190901 : les rotations, quel que soit leur style.
    # Mais pas wtmp.db, qui est du sqlite et se lit ailleurs.
    chemins = sorted(os.path.join(dossier, n) for n in os.listdir(dossier)
                     if n.startswith(nom_fichier)
                     and not n.endswith((".txt", ".db"))) \
        if os.path.isdir(dossier) else []
    poses = 0
    for chemin in chemins:
        poses += _un_utmp(c, chemin, categorie, quoi_defaut)
    return poses


def _un_utmp(c, chemin, categorie, quoi_defaut):
    nom_fichier = os.path.basename(chemin)
    with open(chemin, "rb") as fh:
        blob = fh.read()
    if not blob:
        return 0
    c.lus.add(chemin)
    lignes = lire_utmp(blob)
    if not lignes and blob:
        fait("limite", f"{nom_fichier} illisible", f"{len(blob)} octets",
             c.rel(chemin), "lecture du struct utmp (384 octets)",
             confiance="à vérifier",
             note="taille non multiple de 384 : autre architecture, ou fichier tronqué")
        return 0
    for e in lignes:
        note = f"tty {e['tty']}" if e["tty"] else ""
        if e["ou"]:
            note += f", depuis {e['ou']}"
        if e["type"] == 8:
            note = (note + ", " if note else "") + \
                "fin de la session ouverte sur ce terminal"
        fait(categorie, e["quoi"] if e["type"] != 7 else quoi_defaut,
             e["qui"] or e["tty"] or e["quoi"], c.rel(chemin),
             "lecture directe du binaire (struct utmp)",
             horodatage=e["quand"], acteur=e["qui"] or None,
             note=note or None)
    return len(lignes)


def _bases_connexion(c):
    """lastlog2.db et wtmp.db : du sqlite, depuis Fedora 40 et Debian 13."""
    for chemin in c.chercher(".db", "CONNEXIONS"):
        if chemin.endswith(".txt"):
            continue
        with open(chemin, "rb") as fh:
            blob = fh.read()
        c.lus.add(chemin)
        base = os.path.basename(chemin)
        for nom_table, lignes in _sqlite_lire(blob, [
                ("wtmp", "SELECT User, Login, Logout, TTY, RemoteHost FROM wtmp"),
                ("lastlog2", "SELECT Name, Time, TTY, RemoteHost FROM Lastlog2")]):
            for l in lignes:
                qui, quand = l[0], l[1]
                iso = (datetime.fromtimestamp(quand, timezone.utc).isoformat()
                       .replace("+00:00", "Z")) if isinstance(quand, (int, float)) and quand else None
                detail = f"tty {l[3]}" if len(l) > 3 and l[3] else ""
                if len(l) > 4 and l[4]:
                    detail += f", depuis {l[4]}"
                fait("evenement",
                     "ouverture de session" if nom_table == "wtmp"
                     else "dernière connexion du compte",
                     qui, c.rel(chemin), f"sqlite3 sur la table {nom_table} de {base}",
                     horodatage=iso, acteur=qui, note=detail or None)


def sessions(c):
    if not _last(c, c.un("_sessions.txt", "CONNEXIONS"), "evenement",
                 "ouverture de session", "last -F -f wtmp"):
        _utmp_brut(c, "wtmp", "evenement", "ouverture de session")
    if not _last(c, c.un("_echecs.txt", "CONNEXIONS"), "evenement",
                 "échec d'authentification", "lastb -F -f btmp"):
        _utmp_brut(c, "btmp", "evenement", "échec d'authentification")
    _last(c, c.un("_reboots.txt", "CONNEXIONS"), "evenement",
          "démarrage ou arrêt de la machine", "last -F -x -f wtmp reboot shutdown")
    _bases_connexion(c)

    # lastlog n'a pas de forme texte dans la collecte : il se lit ici ou nulle
    # part. Les uid viennent du passwd emporté à côté.
    ll = os.path.join(c.racine, "CONNEXIONS", "lastlog")
    if os.path.isfile(ll):
        noms = {}
        p = c.un("passwd", "COMPTES")
        if p:
            for l in c.texte(p).splitlines():
                ch = l.split(":")
                if len(ch) > 2 and ch[2].isdigit():
                    noms[int(ch[2])] = ch[0]
        with open(ll, "rb") as fh:
            blob = fh.read()
        c.lus.add(ll)
        for e in lire_lastlog(blob, noms):
            note = f"tty {e['tty']}" if e["tty"] else ""
            if e["ou"]:
                note += f", depuis {e['ou']}"
            fait("evenement", "dernière connexion du compte", e["qui"], c.rel(ll),
                 "lecture directe du binaire (struct lastlog, 292 octets)",
                 horodatage=e["quand"], acteur=e["qui"], note=note or None)


# ── 4 · le journal systemd et /var/log ────────────────────────────────
MOTIFS_JOURNAL = [
    ("evenement", "connexion SSH acceptée",
     re.compile(r'sshd.*Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)'),
     lambda m: (m.group(2), f"depuis {m.group(3)} par {m.group(1)}")),
    ("evenement", "échec SSH",
     re.compile(r'sshd.*Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)'),
     lambda m: (m.group(1), f"depuis {m.group(2)}")),
    ("evenement", "commande sudo",
     re.compile(r'sudo(?:\[\d+\])?:\s+(\S+)\s*:.*COMMAND=(.+)$'),
     lambda m: (m.group(1), f"a lancé {m.group(2).strip()}")),
    ("evenement", "changement d'utilisateur (su)",
     re.compile(r"\bsu(?:\[\d+\])?:.*session opened for user (\S+)(?:\(uid=\d+\))? by (\S+)"),
     lambda m: (m.group(2), f"est devenu {m.group(1)}")),
    ("support", "support amovible USB branché",
     re.compile(r'usb\s+([\d.-]+):\s+New USB device found,\s*(.*)$'),
     lambda m: (None, f"port {m.group(1)}, {m.group(2).strip()}")),
    # Le numéro de série est LA pièce d'identité du support : c'est lui qui
    # permet de dire que la même clé a servi sur une autre machine. Il ne doit
    # pas partager son étiquette avec le modèle.
    ("support", "numéro de série du support USB",
     re.compile(r'usb\s+[\d.-]+:\s+SerialNumber:\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "modèle du support USB",
     re.compile(r'usb\s+[\d.-]+:\s+Product:\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "fabricant du support USB",
     re.compile(r'usb\s+[\d.-]+:\s+Manufacturer:\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "support USB débranché",
     re.compile(r'usb\s+([\d.-]+):\s+USB disconnect, device number (\d+)'),
     lambda m: (None, f"port {m.group(1)}, appareil {m.group(2)}")),
    ("support", "support reconnu par SCSI",
     re.compile(r'scsi\s+[\d:]+:\s+Direct-Access\s+(.+?)\s+PQ:'),
     lambda m: (None, re.sub(r'\s{2,}', " ", m.group(1).strip()))),
    ("support", "disque amovible reconnu",
     re.compile(r'\[(sd[a-z]+)\]\s+Attached SCSI removable disk'),
     lambda m: (None, f"/dev/{m.group(1)}")),
    # .*? et non .* : glouton, il partirait du « /media » de « /run/media ».
    # Le compte est dans le chemin — c'est l'attribution la plus directe qui
    # existe pour un support amovible.
    ("support", "système de fichiers amovible monté",
     re.compile(r'(?:mount|gvfs|udisks).*?((?:/run)?/media/([^/\s]+)/\S*)'),
     lambda m: (m.group(2), m.group(1))),
    ("support", "montage demandé par un compte",
     re.compile(r'on behalf of uid (\d+)'),
     lambda m: (None, f"uid {m.group(1)}")),
    ("machine", "modèle de la machine (DMI du BIOS)",
     re.compile(r'DMI:\s+(.+?),\s*BIOS\s+(.+)$'),
     lambda m: (None, f"{m.group(1).strip()} — BIOS {m.group(2).strip()}")),
    ("reseau", "adresse obtenue en DHCP",
     re.compile(r'dhclient|dhcp4.*address\s+(\d+\.\d+\.\d+\.\d+)', re.I),
     lambda m: (None, m.group(1) if m.lastindex else "bail DHCP")),
]
RE_ISO = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+\-]\d{4})\s+(\S+)\s+(.*)$')
RE_SYSLOG = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$')


def _ligne_journal(ligne, fin_fichier=None):
    """(horodatage ISO ou None, reste de la ligne, année devinée ?).

    Une ligne syslog — « Jan  8 14:02:11 poste sshd[900]: … » — ne porte PAS
    l'année. Sans elle, la ligne n'est pas datable, et c'est le format
    principal de Debian, d'Ubuntu et de RHEL avant le tout-journal.
    On prend alors l'année qui place la ligne juste avant la dernière écriture
    du fichier : logrotate garantit qu'un journal couvre moins d'un an, donc
    une seule année convient. C'est une déduction, elle est marquée comme telle.
    """
    m = RE_ISO.match(ligne)
    if m:
        return m.group(1), m.group(3), False
    m = RE_SYSLOG.match(ligne)
    if not m:
        return None, ligne, False
    if fin_fichier is None:
        return None, m.group(5), False
    mois = MOIS_NOMS.get(_plier(m.group(1)))
    if not mois:
        return None, m.group(5), False
    h, mn, sec = (int(x) for x in m.group(3).split(":"))
    for annee in (fin_fichier.year, fin_fichier.year - 1):
        try:
            d = datetime(annee, mois, int(m.group(2)), h, mn, sec,
                         tzinfo=timezone.utc)
        except ValueError:
            continue
        if d <= fin_fichier:
            return d.isoformat().replace("+00:00", "Z"), m.group(5), True
    return None, m.group(5), False


def journal(c, source_rel, contenu, methode, fin_fichier=None):
    for ligne in contenu.splitlines():
        ts, reste, devine = _ligne_journal(ligne, fin_fichier)
        for categorie, quoi, motif, tire in MOTIFS_JOURNAL:
            m = motif.search(reste)
            if not m:
                continue
            acteur, detail = tire(m)
            fait(categorie, quoi, detail, source_rel, methode,
                 horodatage=ts, acteur=acteur,
                 confiance="forte" if devine else "certaine",
                 note="année déduite de la date du fichier : la ligne syslog "
                      "ne la porte pas" if devine else
                      (None if ts else "ligne sans date exploitable"))
            break


def journaux(c):
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        journal(c, c.rel(j), c.texte(j),
                "journalctl -D var/log/journal -o short-iso, puis motifs")
    tarlog = c.un("_var_log.tar.gz", "JOURNAUX")
    if tarlog:
        interessants = ("secure", "auth.log", "messages", "syslog", "dmesg",
                        "boot.log", "cron", "audit", "maillog", "yum.log")
        dates = c.dates_tar(tarlog)
        for nom, blob in c.membres_tar(tarlog):
            base = os.path.basename(nom)
            fin = (datetime.fromtimestamp(dates[nom], timezone.utc)
                   if dates.get(nom) else None)
            if not any(base.startswith(i) for i in interessants):
                continue
            if nom.endswith((".gz", ".xz", ".lzma", ".bz2", ".zst")):
                clair = decomprimer(nom, blob)
                if clair is None:
                    fait("limite", "journal tourné non décompressé", nom,
                         f"{c.rel(tarlog)} → {nom}", "compresseur non disponible",
                         confiance="à vérifier",
                         note="son contenu n'est PAS dans l'analyse")
                    continue
                blob = clair
            journal(c, f"{c.rel(tarlog)} → {nom}",
                    blob.decode("utf-8", "replace"), "tar -xO, puis motifs", fin)


# ── 5 · réseau ────────────────────────────────────────────────────────
def reseau(c):
    t = c.un("_reseau.tar.gz", "RESEAU")
    if not t:
        return
    for nom, blob in c.membres_tar(t):
        txt = blob.decode("utf-8", "replace")
        base = os.path.basename(nom)
        if "NetworkManager/system-connections" in nom or base.endswith(".nmconnection"):
            for m in re.finditer(r'^\s*(mac-address|cloned-mac-address)\s*=\s*(\S+)',
                                 txt, re.M):
                fait("reseau", "adresse MAC d'une interface", m.group(2),
                     f"{c.rel(t)} → {nom}", "grep mac-address dans le profil NetworkManager",
                     note=f"profil « {base} »")
            for m in re.finditer(r'^\s*address\d*\s*=\s*(\S+)', txt, re.M):
                fait("reseau", "adresse IP configurée", m.group(1),
                     f"{c.rel(t)} → {nom}", "grep address= dans le profil NetworkManager",
                     note=f"profil « {base} »")
            for m in re.finditer(r'^\s*ssid\s*=\s*(.+)$', txt, re.M):
                fait("reseau", "réseau sans fil enregistré", m.group(1).strip(),
                     f"{c.rel(t)} → {nom}", "grep ssid dans le profil NetworkManager",
                     note="la machine s'est associée à ce réseau au moins une fois")
        elif base.startswith("ifcfg-"):
            champs = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', txt, re.M))
            for cle, quoi in (("HWADDR", "adresse MAC d'une interface"),
                              ("IPADDR", "adresse IP configurée"),
                              ("DNS1", "serveur DNS configuré"),
                              ("GATEWAY", "passerelle configurée")):
                if champs.get(cle):
                    fait("reseau", quoi, champs[cle], f"{c.rel(t)} → {nom}",
                         f"grep {cle}= {base}", note=f"interface « {base[6:]} »")
        elif base == "resolv.conf":
            for m in re.finditer(r'^\s*nameserver\s+(\S+)', txt, re.M):
                fait("reseau", "serveur DNS", m.group(1), f"{c.rel(t)} → {nom}",
                     "grep nameserver resolv.conf")
            for m in re.finditer(r'^\s*(?:search|domain)\s+(.+)$', txt, re.M):
                fait("reseau", "domaine de recherche DNS", m.group(1).strip(),
                     f"{c.rel(t)} → {nom}", "grep search resolv.conf",
                     note="souvent le domaine Active Directory")
        elif base == "hosts":
            for m in re.finditer(r'^\s*([\d.:a-fA-F]+)\s+(.+)$', txt, re.M):
                if m.group(1) not in ("127.0.0.1", "::1", "127.0.1.1"):
                    fait("reseau", "hôte déclaré en dur", f"{m.group(1)} {m.group(2).strip()}",
                         f"{c.rel(t)} → {nom}", "cat /etc/hosts", confiance="forte",
                         note="une entrée ajoutée à la main mérite un regard")
        elif "dhcp" in nom and base.endswith((".lease", ".leases")):
            for m in re.finditer(r'fixed-address\s+(\S+);', txt):
                fait("reseau", "adresse IP obtenue en DHCP", m.group(1).rstrip(";"),
                     f"{c.rel(t)} → {nom}", "grep fixed-address dans le bail DHCP")
            for m in re.finditer(r'option dhcp-server-identifier\s+(\S+);', txt):
                fait("reseau", "serveur DHCP", m.group(1).rstrip(";"),
                     f"{c.rel(t)} → {nom}", "grep dhcp-server-identifier")
        elif "known_hosts" in nom:
            for l in txt.splitlines():
                if l.strip() and not l.startswith("#"):
                    fait("reseau", "hôte SSH connu (contacté depuis ce poste)",
                         l.split()[0], f"{c.rel(t)} → {nom}", "cut -d' ' -f1 known_hosts",
                         confiance="forte")


# ── 6 · navigation et téléchargements ─────────────────────────────────
def _sqlite_lire(blob, requetes):
    """Ouvre une base sqlite tenue en mémoire, rend (nom, lignes)."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(blob)
        tmp.flush()
        try:
            cx = sqlite3.connect(f"file:{tmp.name}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error:
            return
        try:
            for nom, sql in requetes:
                try:
                    yield nom, cx.execute(sql).fetchall()
                except sqlite3.Error:
                    continue
        finally:
            cx.close()


# Les visites sont bornées, et la borne est un fait : quand elle est atteinte,
# un fait « limite » dit combien de pages restent hors des faits. Un profil
# de plusieurs années en compte des dizaines de milliers ; la borne se règle
# par --visites. Chaque page porte son nombre de visites et la première : ce
# qui distingue un passage d'une habitude.
FF_EPOCH = "datetime(v.last_visit_date/1000000,'unixepoch')"
REQ_FIREFOX = [
    ("total", "SELECT COUNT(*) FROM moz_places WHERE last_visit_date IS NOT NULL"),
    ("visite", f"SELECT {FF_EPOCH}, v.url, v.title, v.visit_count, "
               "(SELECT datetime(MIN(h.visit_date)/1000000,'unixepoch') "
               " FROM moz_historyvisits h WHERE h.place_id=v.id) "
               "FROM moz_places v WHERE v.last_visit_date IS NOT NULL "
               "ORDER BY v.last_visit_date DESC LIMIT {limite}"),
    ("telechargement",
     "SELECT datetime(a.dateAdded/1000000,'unixepoch'), a.content, p.url "
     "FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
     "WHERE a.content LIKE 'file://%' ORDER BY a.dateAdded DESC LIMIT {limite}"),
]
# Un cookie prouve une visite même quand l'historique a été vidé : les deux
# bases sont indépendantes. On regroupe par domaine — un profil en compte des
# milliers — et on ne sort JAMAIS la colonne « value » : c'est un jeton de
# session, donc un identifiant réutilisable. Le domaine et les dates suffisent
# à établir la visite ; la valeur n'ajoute rien et ferait du rapport un secret.
REQ_COOKIES_FF = [
    ("cookie", "SELECT host, COUNT(*), MIN(creationTime), MAX(lastAccessed) "
               "FROM moz_cookies GROUP BY host ORDER BY MAX(lastAccessed) DESC LIMIT 300"),
    ("cookie (ancien schéma)",
     "SELECT baseDomain, COUNT(*), MIN(creationTime), MAX(lastAccessed) "
     "FROM moz_cookies GROUP BY baseDomain ORDER BY MAX(lastAccessed) DESC LIMIT 300"),
]

# Chrome range ses cookies dans « Cookies » — sous Default/, ou sous
# Default/Network/ depuis Chrome 96. Mêmes colonnes utiles que Firefox, mais
# l'époque est celle de 1601. La valeur y est chiffrée par le trousseau du
# bureau : illisible sans la clé, et on ne la lit pas davantage.
REQ_COOKIES_CHROME = [
    ("cookie", "SELECT host_key, COUNT(*), MIN(creation_utc), MAX(last_access_utc) "
               "FROM cookies GROUP BY host_key ORDER BY MAX(last_access_utc) DESC LIMIT 300"),
]

REQ_CHROME = [
    ("total", "SELECT COUNT(*) FROM urls WHERE last_visit_time > 0"),
    ("visite", "SELECT datetime(u.last_visit_time/1000000-11644473600,'unixepoch'), "
               "u.url, u.title, u.visit_count, "
               "(SELECT datetime(MIN(x.visit_time)/1000000-11644473600,'unixepoch') "
               " FROM visits x WHERE x.url=u.id) "
               "FROM urls u WHERE u.last_visit_time > 0 "
               "ORDER BY u.last_visit_time DESC LIMIT {limite}"),
    ("telechargement",
     "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url "
     "FROM downloads ORDER BY start_time DESC LIMIT {limite}"),
]

# Les mots de passe enregistrés : on lit le SITE, jamais l'identifiant ni le
# secret. Que « intranet.example » ait un mot de passe enregistré dans Firefox
# est un fait utile (une charte l'interdit souvent) ; le nom d'utilisateur
# n'ajoute rien au fait, et le mot de passe est chiffré de toute façon.
REQ_LOGINS_CHROME = [
    ("identifiant", "SELECT origin_url, date_created, date_last_used FROM logins"),
]

BASES_NAVIGATEUR = ("places.sqlite", "cookies.sqlite", "History", "Cookies")


def _iso_z(ts):
    """« 2025-12-19 12:40:00 » de sqlite → « 2025-12-19T12:40:00Z » : c'est de l'UTC."""
    return ts.replace(" ", "T") + "Z" if isinstance(ts, str) and len(ts) == 19 else ts


def _date_us(v, depuis_1601=False):
    """Microsecondes en ISO. Firefox compte depuis 1970, Chrome depuis 1601."""
    if not isinstance(v, (int, float)) or not v:
        return None
    sec = v / 1_000_000 - (11_644_473_600 if depuis_1601 else 0)
    try:
        return (datetime.fromtimestamp(sec, timezone.utc)
                .isoformat().replace("+00:00", "Z"))
    except (OSError, OverflowError, ValueError):
        return None


def _cookies(c, prof, nom, compte, blob, requetes, outil, depuis_1601):
    for _, lignes in _sqlite_lire(blob, requetes):
        for hote, combien, cree, vu in lignes:
            fait("navigation", "domaine ayant posé un cookie", hote,
                 f"{c.rel(prof)} → {nom}",
                 f"sqlite3 sur les cookies {outil}, regroupé par domaine "
                 "(la valeur du cookie n'est pas lue)",
                 horodatage=_date_us(vu, depuis_1601), acteur=compte,
                 note=f"{combien} cookie(s), premier posé le "
                      f"{_date_us(cree, depuis_1601)} — un cookie subsiste "
                      "quand l'historique a été vidé")
        return True
    return False


def _identifiants(c, prof, nom, compte, blob, base):
    """Les sites pour lesquels un mot de passe est enregistré. Le site seul."""
    if base == "logins.json":
        try:
            entrees = json.loads(blob.decode("utf-8", "replace")).get("logins", [])
        except (ValueError, AttributeError):
            return
        for e in entrees:
            if not isinstance(e, dict) or not e.get("hostname"):
                continue
            cree, vu = e.get("timeCreated"), e.get("timeLastUsed")
            fait("usage", "mot de passe enregistré dans le navigateur", e["hostname"],
                 f"{c.rel(prof)} → {nom}",
                 "champ hostname de logins.json (identifiant et mot de passe non lus)",
                 horodatage=_date_us(vu * 1000, False) if vu else None, acteur=compte,
                 note=f"enregistré le {_date_us(cree * 1000, False)}" if cree else None)
    else:
        for _, lignes in _sqlite_lire(blob, REQ_LOGINS_CHROME):
            for site, cree, vu in lignes:
                fait("usage", "mot de passe enregistré dans le navigateur", site,
                     f"{c.rel(prof)} → {nom}",
                     "colonne origin_url de la table logins (identifiant et mot de "
                     "passe non lus)",
                     horodatage=_date_us(vu, True), acteur=compte,
                     note=f"enregistré le {_date_us(cree, True)}" if cree else None)


def navigation(c, limite=5000):
    """Les navigateurs. Ils vivent dans DEUX archives, et l'oublier fait
    manquer un navigateur entier : Firefox est dans ~/.mozilla, donc dans
    _profils ; Chrome ou Chromium installés par paquet sont dans ~/.config,
    donc dans _artefacts. Chromium en snap est dans ~/snap : _profils.
    """
    for suffixe in ("_profils.tar.gz", "_artefacts.tar.gz"):
        for prof in c.chercher(suffixe, "COMPTES"):
            compte = _compte_de(prof, suffixe[1:])
            for nom, blob in c.membres_tar(prof):
                base = os.path.basename(nom)
                if base.endswith(("-wal", "-journal")) and len(blob) > 32 \
                        and base.rsplit("-", 1)[0] in BASES_NAVIGATEUR:
                    fait("limite", "base de navigateur copiée à chaud", nom,
                         f"{c.rel(prof)} → {nom}", "présence d'un fichier -wal non vide",
                         acteur=compte, confiance="à vérifier",
                         note="les visites les plus récentes sont dans ce journal, "
                              "pas dans la base : elles manquent à l'analyse")
                    continue
                if base == "places.sqlite":
                    jeu, outil = REQ_FIREFOX, "Firefox"
                elif base == "cookies.sqlite":
                    _cookies(c, prof, nom, compte, blob, REQ_COOKIES_FF,
                             "Firefox (moz_cookies)", False)
                    continue
                elif base == "Cookies":
                    _cookies(c, prof, nom, compte, blob, REQ_COOKIES_CHROME,
                             "Chromium/Chrome", True)
                    continue
                elif base == "History" and ("chrom" in nom.lower() or "Default" in nom):
                    jeu, outil = REQ_CHROME, "Chromium/Chrome"
                elif base in ("logins.json", "Login Data"):
                    _identifiants(c, prof, nom, compte, blob, base)
                    continue
                else:
                    if base == "recently-used.xbel":
                        for m2 in re.finditer(r'href="([^"]+)"[^>]*(?:added|modified)="([^"]+)"',
                                              blob.decode("utf-8", "replace")):
                            fait("usage", "fichier ouvert récemment", m2.group(1),
                                 f"{c.rel(prof)} → {nom}", "grep href= recently-used.xbel",
                                 horodatage=m2.group(2), acteur=compte)
                    continue
                total = None
                requetes = [(g, q.replace("{limite}", str(limite))) for g, q in jeu]
                for genre, lignes in _sqlite_lire(blob, requetes):
                    if genre == "total":
                        total = lignes[0][0] if lignes else None
                        continue
                    for l in lignes:
                        ts, a, b, combien, premiere = (list(l) + [None] * 5)[:5]
                        ts, premiere = _iso_z(ts), _iso_z(premiere)
                        if genre == "visite":
                            note = f"{combien} visite(s)" if combien else None
                            if premiere and premiere != ts:
                                note += f", la première le {premiere}"
                            if b:
                                note = f"{note} — {b}" if note else b
                            fait("navigation", "page visitée", a,
                                 f"{c.rel(prof)} → {nom}",
                                 f"sqlite3 sur l'historique {outil}",
                                 horodatage=ts, acteur=compte, note=note)
                        else:
                            fait("telechargement", "fichier téléchargé", a,
                                 f"{c.rel(prof)} → {nom}",
                                 f"sqlite3 sur les téléchargements {outil}",
                                 horodatage=ts, acteur=compte,
                                 note=f"depuis {b}" if b else None)
                    if genre == "visite" and total and total > len(lignes):
                        fait("limite", "historique de navigation tronqué",
                             f"{len(lignes)} pages sur {total}", f"{c.rel(prof)} → {nom}",
                             f"COUNT(*) sur l'historique {outil}, borne --visites {limite}",
                             acteur=compte, confiance="certaine",
                             note="les pages les plus anciennes ne sont pas dans les "
                                  "faits ; relancez avec --visites plus grand pour les avoir")


# ── 7 · ce qui se relance seul, et les supprimés ──────────────────────
SUSPECT = [
    (re.compile(r'(nc|ncat|netcat|socat)\s+.*-e\s'), "shell distant (netcat -e)"),
    (re.compile(r'curl\s+[^|]*\|\s*(ba)?sh'), "script téléchargé puis exécuté"),
    (re.compile(r'wget\s+[^|]*\|\s*(ba)?sh'), "script téléchargé puis exécuté"),
    (re.compile(r'/dev/tcp/\d'), "connexion sortante en bash pur"),
    (re.compile(r'base64\s+-d.*\|\s*(ba)?sh'), "commande encodée puis exécutée"),
    (re.compile(r'chattr\s+\+i'), "fichier rendu immuable"),
    (re.compile(r'history\s+-c|unset\s+HISTFILE|HISTSIZE=0'), "effacement de l'historique"),
    (re.compile(r'\bnohup\b.*&\s*$'), "processus détaché"),
    (re.compile(r'ssh-keygen|authorized_keys'), "clé SSH manipulée"),
]


def persistance(c):
    t = c.un("_persistance.tar.gz", "PERSISTANCE")
    if t:
        for nom, blob in c.membres_tar(t):
            txt = blob.decode("utf-8", "replace")
            if "/cron" in nom or "crontab" in nom or "/at" in nom:
                for l in txt.splitlines():
                    l = l.strip()
                    if l and not l.startswith("#") and re.match(r'^[\d*@]', l):
                        fait("persistance", "tâche planifiée", l,
                             f"{c.rel(t)} → {nom}", "lecture des fichiers cron",
                             confiance="certaine")
            if nom.endswith("ld.so.preload") and txt.strip():
                fait("persistance", "bibliothèque préchargée pour tout le système",
                     txt.strip(), f"{c.rel(t)} → {nom}", "cat etc/ld.so.preload",
                     confiance="certaine",
                     note="très rare sur un poste sain — à examiner en premier")
            for motif, quoi in SUSPECT:
                if motif.search(txt):
                    fait("suspect", quoi, nom, f"{c.rel(t)} → {nom}",
                         f"motif « {motif.pattern} » dans le fichier",
                         confiance="à vérifier")

    for art in c.chercher("_artefacts.tar.gz", "COMPTES"):
        compte = _compte_de(art, "artefacts.tar.gz")
        for nom, blob in c.membres_tar(art):
            base = os.path.basename(nom)
            txt = blob.decode("utf-8", "replace")
            if base.endswith(("_history", ".lesshst", ".wget-hsts")):
                lignes = txt.splitlines()
                # bash n'écrit de dates que si HISTTIMEFORMAT était posé : une
                # ligne « #<epoch> » avant chaque commande. Sans elles,
                # l'historique n'est PAS datable — c'est un fait à dire.
                horos = [int(m.group(1)) for m in
                         re.finditer(r'^#(\d{9,11})$', txt, re.M)]
                commandes = [l for l in lignes if l.strip() and not l.startswith("#")]
                if horos:
                    borne = (datetime.fromtimestamp(min(horos), timezone.utc)
                             .isoformat().replace("+00:00", "Z"),
                             datetime.fromtimestamp(max(horos), timezone.utc)
                             .isoformat().replace("+00:00", "Z"))
                    fait("usage", "historique daté (HISTTIMEFORMAT posé)",
                         f"{len(commandes)} commandes, {len(horos)} datées",
                         f"{c.rel(art)} → {nom}",
                         "comptage des lignes « #<epoch> » de l'historique",
                         acteur=compte, horodatage=borne[1],
                         note=f"de {borne[0]} à {borne[1]}")
                else:
                    fait("usage", "historique NON daté",
                         f"{len(commandes)} commandes", f"{c.rel(art)} → {nom}",
                         "absence de lignes « #<epoch> » dans l'historique",
                         acteur=compte, confiance="certaine",
                         note="aucune date dans le fichier : ne datez aucune de "
                              "ces commandes sans une autre source")
                horo_courant = None
                for l in lignes:
                    m = re.match(r'^#(\d{9,11})$', l)
                    if m:
                        horo_courant = (datetime.fromtimestamp(int(m.group(1)),
                                        timezone.utc).isoformat().replace("+00:00", "Z"))
                        continue
                    for motif, quoi in SUSPECT:
                        if motif.search(l):
                            fait("suspect", quoi, l.strip(),
                                 f"{c.rel(art)} → {nom}",
                                 f"motif « {motif.pattern} » dans l'historique",
                                 acteur=compte, horodatage=horo_courant,
                                 confiance="à vérifier",
                                 note=None if horo_courant else
                                      "commande non datée : sa position dans le "
                                      "fichier ne prouve pas son moment")
                            break
            elif base == "known_hosts":
                for l in txt.splitlines():
                    if not l.strip() or l.startswith("#"):
                        continue
                    hote = l.split()[0]
                    hache = hote.startswith("|1|")
                    fait("reseau", "hôte SSH contacté depuis ce compte",
                         "empreinte masquée" if hache else hote,
                         f"{c.rel(art)} → {nom}", "cut -d' ' -f1 .ssh/known_hosts",
                         acteur=compte, confiance="à vérifier" if hache else "forte",
                         note="HashKnownHosts : le nom de l'hôte est illisible"
                              if hache else None)
            elif base == ".viminfo":
                for m in re.finditer(r'^[:>]\s*e?\s*(/\S+)', txt, re.M):
                    fait("usage", "fichier ouvert dans vim", m.group(1),
                         f"{c.rel(art)} → {nom}", "grep des chemins dans .viminfo",
                         acteur=compte,
                         note="viminfo garde le chemin même après suppression")
            elif base == "authorized_keys" and txt.strip():
                for l in txt.splitlines():
                    if l.strip() and not l.startswith("#"):
                        fait("suspect", "clé SSH autorisée à ouvrir ce compte",
                             l.strip()[:120], f"{c.rel(art)} → {nom}",
                             "cat .ssh/authorized_keys", acteur=compte,
                             confiance="certaine",
                             note="permet une entrée sans mot de passe")


def historique_paquets(c):
    """Les journaux du gestionnaire : ce qui a été posé PUIS RETIRÉ.

    « rpm -qa » ne montre que ce qui est installé au moment de la collecte. Un
    paquet posé pour l'occasion puis effacé n'y est plus — il est ici.
    """
    t = c.un("_historique.tar.gz", "PAQUETS")
    if not t:
        return
    for nom, blob in c.membres_tar(t):
        base = os.path.basename(nom)
        if base.endswith((".sqlite", ".sqlite3")):
            for table, lignes in _sqlite_lire(blob, [
                    ("trans", "SELECT dt_begin, cmdline FROM trans ORDER BY dt_begin DESC LIMIT 200"),
                    ("trans (dnf5)", "SELECT dt_start, cmdline FROM trans ORDER BY dt_start DESC LIMIT 200")]):
                for quand, ligne in lignes:
                    iso = None
                    if isinstance(quand, (int, float)) and quand:
                        iso = (datetime.fromtimestamp(quand, timezone.utc)
                               .isoformat().replace("+00:00", "Z"))
                    fait("paquet", "commande du gestionnaire de paquets", ligne,
                         f"{c.rel(t)} → {nom}",
                         f"sqlite3 sur la table {table} de {base}", horodatage=iso)
            continue
        if nom.endswith((".gz", ".xz", ".lzma", ".bz2", ".zst")):
            clair = decomprimer(nom, blob)
            if clair is None:
                continue
            blob = clair
        txt = blob.decode("utf-8", "replace")
        # dpkg.log commence chaque ligne par « AAAA-MM-JJ HH:MM:SS » : la plus
        # ancienne date la pose du système, que dpkg-query -l ne donne pas.
        if base.startswith("dpkg.log"):
            horos = re.findall(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', txt, re.M)
            if horos:
                vieux = min(horos)
                fait("machine", "installation du système (plus ancienne ligne de dpkg.log)",
                     vieux, f"{c.rel(t)} → {nom}", "première date de var/log/dpkg.log",
                     horodatage=vieux.replace(" ", "T"), confiance="forte",
                     note="sur Debian et Ubuntu, dpkg-query -l ne date rien : "
                          "c'est ici que la pose du système se lit")
        if base.startswith("history.log"):
            for bloc in txt.split("Start-Date:"):
                d = re.match(r'\s*(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)', bloc)
                cmd = re.search(r'^Commandline:\s*(.+)$', bloc, re.M)
                if d and cmd:
                    fait("paquet", "commande du gestionnaire de paquets",
                         cmd.group(1).strip(), f"{c.rel(t)} → {nom}",
                         "blocs Start-Date/Commandline de apt/history.log",
                         horodatage=f"{d.group(1)}T{d.group(2)}")
            continue
        for l in txt.splitlines():
            if re.search(r'\b(Erased|Removed|remove|purge)\b', l):
                m = re.match(r'^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)', l)
                fait("paquet", "paquet retiré", l.strip()[:160],
                     f"{c.rel(t)} → {nom}",
                     "grep 'Erased|remove' dans le journal du gestionnaire",
                     horodatage=f"{m.group(1)}T{m.group(2)}" if m else None,
                     confiance="forte",
                     note="absent de la liste des paquets installés : seule trace")


def supprimes(c):
    for d in ("SUPPRIMES", "PHOTOREC"):
        base = os.path.join(c.racine, d)
        if not os.path.isdir(base):
            continue
        n = sum(len(f) for _, _, f in os.walk(base))
        if n:
            fait("recuperation", f"pièces récupérées dans {d}/", str(n),
                 d + "/", "find | wc -l",
                 note="xfs_undelete rend des blocs entiers ; photorec coupe juste"
                      " mais ignore ce dont il n'a pas la signature")


# ── 8 · la timeline du système de fichiers ────────────────────────────
def timeline(c):
    csv = c.un("_mactime.csv", "TIMELINE")
    if not csv:
        return
    lignes = c.texte(csv, 40_000_000).splitlines()
    fait("timeline", "entrées dans la timeline du système de fichiers",
         str(max(0, len(lignes) - 1)), c.rel(csv),
         "mactime -b corps -d, puis wc -l",
         note="corps lus sur le périphérique quand un lecteur existait")
    interet = re.compile(r'/(\.ssh/|Downloads?/|T[ée]l[ée]chargements?/|media/|run/media/'
                         r'|tmp/\.|\.bash_history|authorized_keys|/root/)', re.I)
    vus = 0
    for l in lignes[1:]:
        if vus >= 300:
            break
        if not interet.search(l):
            continue
        ch = l.split(",", 7)
        if len(ch) < 8:
            continue
        vus += 1
        fait("timeline", "activité sur un chemin sensible", ch[7].strip('"'),
             c.rel(csv), "grep de chemins d'intérêt dans la timeline mactime",
             horodatage=ch[0], note=f"{ch[2]} {ch[3]}")


# ── mise en ordre ─────────────────────────────────────────────────────
def decomprimer(nom, blob):
    """Le contenu d'un journal tourné, quel que soit son compresseur.

    logrotate emploie gzip par défaut, mais xz et bzip2 se rencontrent, et
    zstd sur les distributions récentes. Rend None si on ne sait pas ouvrir :
    l'appelant en fait un fait, pour que le silence ne passe pas pour une
    absence de preuve.
    """
    try:
        if nom.endswith(".gz"):
            return gzip.decompress(blob)
        if nom.endswith((".xz", ".lzma")):
            return lzma.decompress(blob)
        if nom.endswith(".bz2"):
            return bz2.decompress(blob)
        if nom.endswith(".zst"):
            try:
                from compression import zstd            # Python 3.14+
                return zstd.decompress(blob)
            except ImportError:
                try:
                    import zstandard                    # si le paquet est là
                    return zstandard.ZstdDecompressor().stream_reader(
                        io.BytesIO(blob)).read()
                except ImportError:
                    return None
    except (OSError, EOFError, lzma.LZMAError, ValueError):
        return None
    return blob


# ── les fichiers de connexion en binaire ─────────────────────────────
# struct utmp (Linux, 64 bits) : 384 octets. ut_type tient sur un short
# suivi de deux octets de bourrage — un int32 les lit d'un coup.
UTMP = struct.Struct("<ii32s4s32s256shhiii16s20s")
UTMP_TYPE = {1: "changement de niveau d'exécution", 2: "démarrage de la machine",
             5: "service lancé", 6: "invite de connexion",
             7: "ouverture de session", 8: "fermeture de session"}
# struct lastlog : 292 octets, indexé par uid.
LASTLOG = struct.Struct("<i32s256s")


def _txt(champ):
    return champ.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def lire_utmp(blob):
    """Les enregistrements d'un wtmp ou d'un btmp. Rien si la taille ne colle pas."""
    if not blob or len(blob) % UTMP.size:
        return []
    sorties = []
    for pos in range(0, len(blob), UTMP.size):
        (typ, _pid, ligne, _id, user, host, _t, _e, _s,
         sec, _usec, _addr, _libre) = UTMP.unpack_from(blob, pos)
        if typ not in UTMP_TYPE or not sec:
            continue
        sorties.append({"type": typ, "quoi": UTMP_TYPE[typ], "tty": _txt(ligne),
                        "qui": _txt(user), "ou": _txt(host),
                        "quand": datetime.fromtimestamp(sec, timezone.utc)
                                         .isoformat().replace("+00:00", "Z")})
    return sorties


def lire_lastlog(blob, noms_par_uid):
    """La dernière connexion de chaque compte. Une entrée de 292 octets par uid."""
    if not blob or len(blob) % LASTLOG.size:
        return []
    sorties = []
    for uid in range(len(blob) // LASTLOG.size):
        sec, ligne, host = LASTLOG.unpack_from(blob, uid * LASTLOG.size)
        if not sec:
            continue
        sorties.append({"uid": uid, "qui": noms_par_uid.get(uid, f"uid {uid}"),
                        "tty": _txt(ligne), "ou": _txt(host),
                        "quand": datetime.fromtimestamp(sec, timezone.utc)
                                         .isoformat().replace("+00:00", "Z")})
    return sorties


# ── ce que la collecte devrait contenir ──────────────────────────────
# (dossier, motif, ce que c'est, chemin D'ORIGINE sur le système, étape de
#  collecte-linux.conf à rejouer, quand l'absence est normale)
ATTENDU = [
    ("SYSTEME", "hostname", "le nom de la machine", "/etc/hostname",
     "Nom de la machine (/etc/hostname)", None),
    ("SYSTEME", "os-release", "la distribution", "/etc/os-release",
     "Distribution (/etc/os-release)", None),
    ("SYSTEME", "_localtime.txt", "le fuseau du poste", "/etc/localtime",
     "Fuseau horaire", None),
    ("SYSTEME", "_installation.tar.gz", "l'identité et la pose du système",
     "/etc/machine-id, /etc/adjtime, /var/log/anaconda, /var/log/installer",
     "Identité et installation", None),
    ("SYSTEME", "_fs_", "le système de fichiers", "le périphérique lui-même",
     "Système de fichiers de {{volume}}", None),
    ("PAQUETS", "_paquets.txt", "la liste des paquets",
     "/var/lib/rpm ou /var/lib/dpkg",
     "Paquets installés", "l'image n'a ni base RPM ni base dpkg"),
    ("PAQUETS", "_historique.tar.gz", "l'historique du gestionnaire",
     "/var/log/dpkg.log, /var/log/apt, /var/log/yum.log, /var/lib/dnf",
     "Historique des installations", None),
    ("COMPTES", "passwd", "les comptes locaux", "/etc/passwd",
     "Comptes déclarés (/etc/passwd, /etc/group)", None),
    ("COMPTES", "_droits.tar.gz", "shadow, sudoers, PAM, SELinux",
     "/etc/shadow, /etc/sudoers, /etc/pam.d, /etc/selinux",
     "Droits (shadow, sudoers, login.defs)", None),
    ("COMPTES", "_domaine.tar.gz", "l'appartenance à un domaine",
     "/etc/sssd, /etc/krb5.conf, /etc/samba, /var/lib/sss/db",
     "Domaine et annuaire", None),
    ("COMPTES", "_artefacts.tar.gz", "les traces des comptes",
     "~/.bash_history, ~/.ssh, ~/.viminfo de chaque compte",
     "Artefacts de {{compte}}", "aucun compte n'a de dossier sur l'image"),
    ("COMPTES", "_profils.tar.gz", "les profils applicatifs",
     "~/.mozilla, ~/.config, ~/.local, ~/snap, ~/.var/app",
     "Caches et profils applicatifs de {{compte}}",
     "aucun compte n'a de dossier, ou l'étape a été passée (elle est lourde)"),
    ("CONNEXIONS", ("wtmp", "_sessions.txt"), "les sessions",
     "/var/log/wtmp et ses rotations, ou /var/lib/wtmpdb/wtmp.db",
     "Copie des fichiers de connexion",
     "Fedora 40+ et Debian 13+ n'ont plus wtmp, mais wtmp.db"),
    ("CONNEXIONS", ("btmp", "_echecs.txt"), "les échecs d'authentification",
     "/var/log/btmp et ses rotations", "Copie des fichiers de connexion",
     "btmp est souvent absent ou désactivé"),
    ("JOURNAUX", "_journal.txt", "le journal systemd en clair",
     "/var/log/journal/<machine-id>/*.journal", "Journal systemd, en clair",
     "l'image n'a pas de journal persistant sur disque"),
    ("JOURNAUX", "_var_log.tar.gz", "tout /var/log", "/var/log",
     "Archive de /var/log", None),
    ("RESEAU", "_reseau.tar.gz", "interfaces, DNS, pare-feu, ssh",
     "/etc/NetworkManager, /etc/sysconfig/network-scripts, /etc/resolv.conf,"
     " /etc/ssh, /var/lib/dhclient", "Réseau : profils, hosts, ssh, baux", None),
    ("PERSISTANCE", "_persistance.tar.gz", "ce qui se relance seul",
     "/etc/cron*, /etc/systemd, /etc/rc.local, /etc/ld.so.preload",
     "Persistance", None),
    ("TIMELINE", "_mactime.csv", "la chronologie du disque",
     "le périphérique, ou le montage", "Timeline mactime", None),
    ("TIMELINE", ("_body.mactime", "_mactime.csv"), "le corps de la timeline",
     "le périphérique", "Corps de la timeline", None),
]


def completude(c):
    """Ce qui manque, et où le reprendre.

    Une pièce absente n'est pas la même chose selon la cause : ou bien le
    système ne l'avait pas — et c'est un fait sur ce système —, ou bien la
    collecte l'a ratée, et il faut y retourner. On ne peut pas trancher d'ici,
    mais on peut donner au lecteur de quoi trancher : le chemin d'origine et
    l'étape à rejouer.
    """
    for dossier, motif, quoi, origine, etape, normal in ATTENDU:
        # Plusieurs motifs = plusieurs formes acceptables de la même pièce :
        # le binaire wtmp OU la sortie texte de « last » suffisent.
        motifs = motif if isinstance(motif, tuple) else (motif,)
        if any(c.chercher(m, dossier) for m in motifs):
            continue
        note = (f"à reprendre sur l'image montée : {origine}. "
                f"Étape de collecte-linux.conf : « {etape} » — "
                f"la rejouer seule avec --only <numéro du plan>.")
        if normal:
            note += f" Absence normale si {normal}."
        fait("limite", f"pièce absente de la collecte : {quoi}",
             " ou ".join(f"{dossier}/…{m}" for m in motifs), dossier + "/",
             "recherche du motif dans la collecte",
             confiance="à vérifier", note=note)


def empreinte(chemin, taille_bloc=1 << 20):
    """SHA-256 d'un fichier, lu par blocs."""
    h = hashlib.sha256()
    with open(chemin, "rb") as fh:
        for bloc in iter(lambda: fh.read(taille_bloc), b""):
            h.update(bloc)
    return h.hexdigest()


def manifeste(c, sortie, argv):
    """Ce qui prouve QUELS octets ont été analysés, et par quel outil.

    Le manifeste porte une date : il décrit l'exécution, pas les pièces. Les
    faits, eux, ne dépendent que de la collecte — deux extractions de la même
    collecte rendent le même fichier de faits, à l'octet près.
    """
    moi = os.path.abspath(__file__)
    pieces = {}
    for chemin in sorted(c.lus):
        try:
            pieces[c.rel(chemin)] = {"sha256": empreinte(chemin),
                                     "octets": os.path.getsize(chemin)}
        except OSError:
            continue
    par_cat = {}
    for f in FAITS:
        par_cat[f["categorie"]] = par_cat.get(f["categorie"], 0) + 1
    return {
        "collecte": c.prefix,
        "chemin_analyse": c.racine,
        "extracteur": {"fichier": os.path.basename(moi),
                       "sha256": empreinte(moi)},
        "commande": " ".join(argv),
        "extrait_le": datetime.now().astimezone().isoformat(),
        "faits": {"total": len(FAITS), "par_categorie": dict(sorted(par_cat.items()))},
        "faits_sha256": hashlib.sha256(
            open(sortie, "rb").read()).hexdigest(),
        "pieces_lues": pieces,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("collecte", help="le dossier PREFIX/ produit par collecte-linux")
    ap.add_argument("-o", "--sortie", default="faits.jsonl")
    ap.add_argument("--visites", type=int, default=5000, metavar="N",
                    help="pages retenues par historique de navigateur, les plus "
                         "récentes d'abord (défaut 5000) ; au-delà, un fait "
                         "« limite » le dit")
    args = ap.parse_args()

    c = Collecte(args.collecte)
    for etape, fn in (("complétude", completude),
                      ("machine", machine), ("comptes et domaine", comptes),
                      ("sessions", sessions), ("journaux", journaux),
                      ("réseau", reseau),
                      ("navigation", lambda c: navigation(c, args.visites)),
                      ("historique des paquets", historique_paquets),
                      ("persistance", persistance), ("supprimés", supprimes),
                      ("timeline", timeline)):
        avant = len(FAITS)
        try:
            fn(c)
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! {etape} : {type(e).__name__} {e}", file=sys.stderr)
        print(f"  {etape:22s} {len(FAITS) - avant:5d} faits", file=sys.stderr)

    with open(args.sortie, "w", encoding="utf-8") as fh:
        for f in FAITS:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    chemin_man = os.path.splitext(args.sortie)[0] + "-manifeste.json"
    with open(chemin_man, "w", encoding="utf-8") as fh:
        json.dump(manifeste(c, args.sortie, sys.argv), fh,
                  ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")

    par_cat = {}
    for f in FAITS:
        par_cat[f["categorie"]] = par_cat.get(f["categorie"], 0) + 1
    print(f"\n{len(FAITS)} faits → {args.sortie}", file=sys.stderr)
    print(f"  empreintes des pièces lues → {chemin_man}", file=sys.stderr)
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(par_cat.items())),
          file=sys.stderr)


if __name__ == "__main__":
    main()
