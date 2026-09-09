#!/usr/bin/env python3
"""Extrait des FAITS datés et sourcés d'une collecte tasker.sh collecte-linux.

    extraire.py <dossier de collecte> [-o faits.jsonl]

Chaque fait porte d'où il vient et comment il a été obtenu : un lecteur doit
pouvoir refaire le geste à la main. Rien n'est interprété ici — le tri, le
recoupement et le jugement sont le travail du rapport.

Bibliothèque standard seulement. La collecte n'est jamais modifiée : les
archives sont lues en flux, jamais dépaquetées sur place.
"""
import argparse, gzip, hashlib, io, json, os, re, sqlite3, sys, tarfile, tempfile
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
                    yield m.name.lstrip("./"), fh.read()
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
            elif "anaconda" in nom or "installer" in nom:
                fait("machine", "trace d'installation", nom,
                     f"{c.rel(inst)} → {nom}", "tar -t",
                     note="journal de l'installateur : la date de pose du système")

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
    if not chemin:
        return
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


def sessions(c):
    _last(c, c.un("_sessions.txt", "CONNEXIONS"), "evenement",
          "ouverture de session", "last -F -f wtmp")
    _last(c, c.un("_echecs.txt", "CONNEXIONS"), "evenement",
          "échec d'authentification", "lastb -F -f btmp")
    _last(c, c.un("_reboots.txt", "CONNEXIONS"), "evenement",
          "démarrage ou arrêt de la machine", "last -F -x -f wtmp reboot shutdown")


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
    ("support", "modèle du support USB",
     re.compile(r'usb\s+[\d.-]+:\s+(?:Product|Manufacturer|SerialNumber):\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "disque amovible reconnu",
     re.compile(r'\[(sd[a-z]+)\]\s+Attached SCSI removable disk'),
     lambda m: (None, f"/dev/{m.group(1)}")),
    ("support", "système de fichiers amovible monté",
     re.compile(r'(?:mount|gvfs|udisks).*((?:/run)?/media/\S+)'),
     lambda m: (None, m.group(1))),
    ("reseau", "adresse obtenue en DHCP",
     re.compile(r'dhclient|dhcp4.*address\s+(\d+\.\d+\.\d+\.\d+)', re.I),
     lambda m: (None, m.group(1) if m.lastindex else "bail DHCP")),
]
RE_ISO = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+\-]\d{4})\s+(\S+)\s+(.*)$')
RE_SYSLOG = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$')


def _ligne_journal(ligne):
    """(horodatage ISO ou None, reste de la ligne)."""
    m = RE_ISO.match(ligne)
    if m:
        return m.group(1), m.group(3)
    m = RE_SYSLOG.match(ligne)
    if m:
        return None, m.group(5)
    return None, ligne


def journal(c, source_rel, contenu, methode):
    for ligne in contenu.splitlines():
        ts, reste = _ligne_journal(ligne)
        for categorie, quoi, motif, tire in MOTIFS_JOURNAL:
            m = motif.search(reste)
            if not m:
                continue
            acteur, detail = tire(m)
            fait(categorie, quoi, detail, source_rel, methode,
                 horodatage=ts, acteur=acteur,
                 note=None if ts else "date relevée dans la ligne brute")
            break


def journaux(c):
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        journal(c, c.rel(j), c.texte(j),
                "journalctl -D var/log/journal -o short-iso, puis motifs")
    tarlog = c.un("_var_log.tar.gz", "JOURNAUX")
    if tarlog:
        interessants = ("secure", "auth.log", "messages", "syslog", "dmesg",
                        "boot.log", "cron")
        for nom, blob in c.membres_tar(tarlog):
            base = os.path.basename(nom)
            if not any(base.startswith(i) for i in interessants):
                continue
            if nom.endswith(".gz"):
                try:
                    blob = gzip.decompress(blob)
                except OSError:
                    continue
            journal(c, f"{c.rel(tarlog)} → {nom}",
                    blob.decode("utf-8", "replace"), "tar -xO, puis motifs")


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


FF_EPOCH = "datetime(v.last_visit_date/1000000,'unixepoch')"
REQ_FIREFOX = [
    ("visite", f"SELECT {FF_EPOCH}, v.url, v.title FROM moz_places v "
               "WHERE v.last_visit_date IS NOT NULL ORDER BY v.last_visit_date DESC LIMIT 400"),
    ("telechargement",
     "SELECT datetime(a.dateAdded/1000000,'unixepoch'), a.content, p.url "
     "FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
     "WHERE a.content LIKE 'file://%' ORDER BY a.dateAdded DESC LIMIT 200"),
]
REQ_CHROME = [
    ("visite", "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url, title "
               "FROM urls ORDER BY last_visit_time DESC LIMIT 400"),
    ("telechargement",
     "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url "
     "FROM downloads ORDER BY start_time DESC LIMIT 200"),
]


def navigation(c):
    for prof in c.chercher("_profils.tar.gz", "COMPTES"):
        # PREFIX_<compte>_profils.tar.gz
        m = re.search(r'_([^_]+)_profils\.tar\.gz$', os.path.basename(prof))
        compte = m.group(1) if m else "?"
        for nom, blob in c.membres_tar(prof):
            base = os.path.basename(nom)
            if base == "places.sqlite":
                jeu, outil = REQ_FIREFOX, "Firefox"
            elif base == "History" and ("chrom" in nom.lower() or "Default" in nom):
                jeu, outil = REQ_CHROME, "Chromium/Chrome"
            else:
                if base == "recently-used.xbel":
                    for m2 in re.finditer(r'href="([^"]+)"[^>]*(?:added|modified)="([^"]+)"',
                                          blob.decode("utf-8", "replace")):
                        fait("usage", "fichier ouvert récemment", m2.group(1),
                             f"{c.rel(prof)} → {nom}", "grep href= recently-used.xbel",
                             horodatage=m2.group(2), acteur=compte)
                continue
            for genre, lignes in _sqlite_lire(blob, jeu):
                for l in lignes:
                    ts, a, b = (list(l) + [None, None, None])[:3]
                    if genre == "visite":
                        fait("navigation", "page visitée", a,
                             f"{c.rel(prof)} → {nom}",
                             f"sqlite3 sur l'historique {outil}",
                             horodatage=ts, acteur=compte,
                             note=(b or None))
                    else:
                        fait("telechargement", "fichier téléchargé", a,
                             f"{c.rel(prof)} → {nom}",
                             f"sqlite3 sur les téléchargements {outil}",
                             horodatage=ts, acteur=compte,
                             note=f"depuis {b}" if b else None)


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
        m = re.search(r'_([^_]+)_artefacts\.tar\.gz$', os.path.basename(art))
        compte = m.group(1) if m else "?"
        for nom, blob in c.membres_tar(art):
            base = os.path.basename(nom)
            txt = blob.decode("utf-8", "replace")
            if base.endswith("_history") or base in (".bash_history", ".zsh_history"):
                for l in txt.splitlines():
                    for motif, quoi in SUSPECT:
                        if motif.search(l):
                            fait("suspect", quoi, l.strip(),
                                 f"{c.rel(art)} → {nom}",
                                 f"motif « {motif.pattern} » dans l'historique du shell",
                                 acteur=compte, confiance="à vérifier")
                            break
                fait("usage", "historique de commandes présent",
                     f"{len(txt.splitlines())} lignes", f"{c.rel(art)} → {nom}",
                     "wc -l sur l'historique du shell", acteur=compte)
            elif base == "authorized_keys" and txt.strip():
                for l in txt.splitlines():
                    if l.strip() and not l.startswith("#"):
                        fait("suspect", "clé SSH autorisée à ouvrir ce compte",
                             l.strip()[:120], f"{c.rel(art)} → {nom}",
                             "cat .ssh/authorized_keys", acteur=compte,
                             confiance="certaine",
                             note="permet une entrée sans mot de passe")


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
    args = ap.parse_args()

    c = Collecte(args.collecte)
    for etape, fn in (("machine", machine), ("comptes et domaine", comptes),
                      ("sessions", sessions), ("journaux", journaux),
                      ("réseau", reseau), ("navigation", navigation),
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
