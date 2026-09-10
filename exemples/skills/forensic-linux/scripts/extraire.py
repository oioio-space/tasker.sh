#!/usr/bin/env python3
"""Extrait des FAITS datés et sourcés d'une collecte tasker.sh collecte-linux.

    extraire.py <dossier de collecte> [-o faits.jsonl]

Chaque fait porte d'où il vient et comment il a été obtenu : un lecteur doit
pouvoir refaire le geste à la main. Rien n'est interprété ici — le tri, le
recoupement et le jugement sont le travail du rapport.

Bibliothèque standard seulement. La collecte n'est jamais modifiée : les
archives sont lues en flux, jamais dépaquetées sur place.
"""
import argparse, bz2, collections, contextlib, csv, fnmatch, gzip, hashlib, io, json, lzma, os, re
import urllib.parse
import sqlite3, struct, sys, tarfile, tempfile, zlib
from datetime import datetime, timezone

COLONNES_CSV = ("id", "categorie", "fait", "valeur", "horodatage", "acteur", "confiance",
                "source", "methode", "note")

FAITS = []


RE_CONTROLE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _propre(v):
    """Une valeur tirée d'une pièce peut porter des octets de contrôle — un
    contexte pris dans une base binaire, un nom de fichier forgé. Ils n'ont
    rien à faire dans un rapport, un CSV ou un terminal : un point médian."""
    return RE_CONTROLE.sub("·", v) if isinstance(v, str) else v


def fait(categorie, quoi, valeur, source, methode, horodatage=None, acteur=None,
         confiance="certaine", note=None, **champs):
    """Pose un fait. source = chemin dans la collecte ; methode = le geste.

    Les champs nommés en plus (tty, origine, fin, cible…) sont des données
    structurées : ce que le rapport doit pouvoir lire sans relire une phrase.
    """
    f = {"id": f"F{len(FAITS) + 1:04d}", "categorie": categorie, "fait": quoi,
         "valeur": valeur, "source": source, "methode": methode}
    for k, v in (("horodatage", horodatage), ("acteur", acteur),
                 ("confiance", confiance), ("note", note), *champs.items()):
        if v is not None:
            f[k] = v
    f = {k: _propre(v) for k, v in f.items()}
    FAITS.append(f)
    return f


def _epoch_iso(n):
    return datetime.fromtimestamp(n, timezone.utc).isoformat().replace("+00:00", "Z")


RE_CLE_VALEUR = re.compile(r'^([A-Z_]+)="?([^"\n]*)"?$', re.M)


def _champs(txt, motif=RE_CLE_VALEUR):
    """« CLE=valeur » ligne à ligne → dict. os-release, machine-info, ifcfg."""
    return dict(motif.findall(txt))


def _compte_de(chemin, suffixe):
    """PREFIX_<compte>_<suffixe> → compte."""
    m = re.search(rf'_([^_]+)_{re.escape(suffixe)}$', os.path.basename(chemin))
    return m.group(1) if m else "?"


# ── accès à la collecte ───────────────────────────────────────────────
class Collecte:
    """Le dossier PREFIX/ produit par collecte-linux."""

    def __init__(self, racine, visites=5000):
        self.racine = os.path.abspath(racine)
        self.prefix = os.path.basename(self.racine)
        self.lus = set()          # ce qui a servi, pour le manifeste
        self.mtimes = {}          # archive → {membre: date}, rempli en lisant
        self.visites = visites    # pages retenues par historique de navigateur
        if not os.path.isdir(self.racine):
            sys.exit(f"pas un dossier : {self.racine}")
        # os-release, lu une fois : les faits « machine » en viennent, et la
        # famille du système décide de ce qui est normal ou non, dès la
        # vérification de complétude
        self.os_release = self.un("os-release", "SYSTEME")
        champs = _champs(self.texte(self.os_release)) if self.os_release else {}
        self.familles = {x.lower() for k in ("ID", "ID_LIKE") for x in champs.get(k, "").split()}

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

    def lignes(self, chemin):
        """Les lignes d'un gros fichier texte, sans le tenir en mémoire."""
        self.lus.add(chemin)
        try:
            with open(chemin, encoding="utf-8", errors="replace") as fh:
                for l in fh:
                    yield l.rstrip("\n")
        except OSError:
            return

    def dates_tar(self, archive):
        """La date de chaque membre. tar la conserve : c'est souvent la seule
        façon de dater une pièce dont le contenu n'est pas horodaté.
        Une archive déjà lue ne se relit pas : membres_tar a noté les dates."""
        if archive not in self.mtimes:
            for _ in self.membres_tar(archive, lambda nom: False):
                pass
        return self.mtimes.get(archive, {})

    def membres_tar(self, archive, garde=None):
        """(nom, contenu) des fichiers d'un .tar.gz — ceux que garde(nom) accepte.

        Le filtre passe AVANT la lecture : /var/log porte des journaux binaires
        de centaines de Mo qu'aucun motif ne regarde. Les dates de TOUS les
        membres sont notées au passage, dans self.mtimes.
        """
        self.lus.add(archive)
        dates = self.mtimes.setdefault(archive, {})
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m in t:
                    if not m.isfile():
                        continue
                    # lstrip("./") mangerait le point d'un fichier caché :
                    # « ./.viminfo » deviendrait « viminfo ».
                    nom = m.name[2:] if m.name.startswith("./") else m.name
                    dates[nom] = m.mtime
                    if garde and not garde(nom):
                        continue
                    fh = t.extractfile(m)
                    if fh is not None:
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

    osr = c.os_release
    if osr:
        champs = _champs(c.texte(osr))
        for cle, quoi in (("PRETTY_NAME", "système installé"),
                          ("VERSION_ID", "version du système"),
                          ("ID", "famille du système"),
                          ("ID_LIKE", "parenté du système")):
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
                champs = _champs(blob.decode("utf-8", "replace"))
                for cle, quoi in (("PRETTY_HOSTNAME", "nom affiché de la machine"),
                                  ("CHASSIS", "type de châssis"),
                                  ("DEPLOYMENT", "environnement déclaré")):
                    if champs.get(cle):
                        fait("machine", quoi, champs[cle], f"{c.rel(inst)} → {nom}",
                             f"grep {cle}= etc/machine-info")
            elif nom.endswith("-ks.cfg"):
                txt = blob.decode("utf-8", "replace")
                for motif, quoi in (
                        (r'^\s*user\s+.*--name[= ](\S+)', "compte créé à l'installation"),
                        (r'^\s*network\s+.*--hostname[= ](\S+)', "nom donné à l'installation"),
                        (r'^\s*timezone\s+(\S+)', "fuseau choisi à l'installation"),
                        (r'^\s*rootpw\s+(--iscrypted|--plaintext|--lock)', "mot de passe root à l'installation")):
                    for m in re.finditer(motif, txt, re.M):
                        fait("machine", quoi, m.group(1), f"{c.rel(inst)} → {nom}",
                             "lecture du fichier kickstart", confiance="forte",
                             note="ce que l'installation automatique a posé — la "
                                  "configuration d'origine, avant tout usage")
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
            iso = _epoch_iso(quand) if quand else None
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

    # Arch : chaque dossier de var/lib/pacman/local porte « desc », avec la
    # date de pose en epoch. La plus ancienne date l'installation, la plus
    # récente la dernière administration.
    pacman = c.un("_pacman_local.tar.gz", "PAQUETS")
    compte_paquets = None                          # (nombre, source, méthode, note)
    if pacman:
        poses = []
        for nom, blob in c.membres_tar(pacman, lambda n: n.endswith("/desc")):
            champs = _champs(blob.decode("utf-8", "replace"), RE_CLE_PACMAN)
            if champs.get("NAME") and champs.get("INSTALLDATE", "").isdigit():
                poses.append((int(champs["INSTALLDATE"]), champs["NAME"]))
        poses.sort()
        if poses:
            fait("machine", "installation du système (plus ancien paquet posé)",
                 poses[0][1], f"{c.rel(pacman)} → desc", "%INSTALLDATE% le plus ancien de pacman",
                 horodatage=_epoch_iso(poses[0][0]), confiance="forte")
            fait("machine", "dernier paquet installé", poses[-1][1],
                 f"{c.rel(pacman)} → desc", "%INSTALLDATE% le plus récent de pacman",
                 horodatage=_epoch_iso(poses[-1][0]))
            compte_paquets = (len(poses), c.rel(pacman), "compte des dossiers de var/lib/pacman/local", None)
    apk = c.un("_apk_installed.txt", "PAQUETS")
    if apk:
        noms = re.findall(r'^P:(\S+)$', c.texte(apk), re.M)
        compte_paquets = (len(noms), c.rel(apk), "compte des champs P: de lib/apk/db/installed",
                          "apk ne date pas les poses : voir etc/apk/world et var/log/apk.log")

    # Les montages déclarés : quels volumes cette machine avait, y compris
    # ceux qui ne sont pas dans la collecte (réseau, chiffrés, amovibles).
    fs = c.un("fstab", "SYSTEME")
    if fs:
        for l in c.texte(fs).splitlines():
            l = l.strip()
            if not l or l.startswith("#"):
                continue
            ch = l.split()
            if len(ch) < 3 or ch[1] == "none":
                continue
            quoi = ("montage réseau déclaré" if ch[2] in ("nfs", "nfs4", "cifs", "smbfs")
                    else "montage déclaré")
            fait("machine", quoi, f"{ch[0]} → {ch[1]} ({ch[2]})", c.rel(fs),
                 "colonnes de /etc/fstab", confiance="certaine",
                 note="déclaré au démarrage ; sa présence dans la collecte est une "
                      "autre question" if ch[1] not in ("/", "swap") else None)

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
                 horodatage=iso or vieux, confiance="forte", fuseau="poste d'analyse",
                 note="date de la salve d'installation, pas une preuve directe")
            recent, paquet_r = dates[0]
            fait("machine", "dernier paquet installé", paquet_r, c.rel(pk),
                 "rpm -qa --last | head -n 1",
                 horodatage=lire_date(recent) or recent, fuseau="poste d'analyse",
                 note="borne basse de la dernière utilisation administrative")
        # dpkg-query -l pose cinq lignes d'en-tête avant la liste : seules
        # celles qui commencent par un état à deux lettres sont des paquets.
        dpkg = [l for l in lignes if re.match(r'^[a-zA-Z]{2}\s+\S', l)]
        if compte_paquets is None and lignes:      # une liste vide est une limite, pas « 0 paquet »
            if dpkg and not dates:
                compte_paquets = (len(dpkg), c.rel(pk), "compte des lignes d'état de dpkg-query -l",
                                  "dpkg ne date pas les installations : voir le journal "
                                  "du gestionnaire pour les dates")
            else:
                compte_paquets = (len(lignes), c.rel(pk), "wc -l", None)
    if compte_paquets:
        n, source, methode, note = compte_paquets
        fait("machine", "paquets installés (nombre)", str(n), source, methode, note=note)


# ── 2 · comptes et domaine ────────────────────────────────────────────
def _dates_dossiers(c):
    """« stat » du dossier de chaque compte : quand il a été créé, et quand
    quelque chose y a touché pour la dernière fois."""
    for f in c.chercher("_stat.txt", "COMPTES"):
        compte = _compte_de(f, "stat.txt")
        for cle, quoi in (("Modify", "dernière écriture dans le dossier du compte"),
                          ("Birth", "création du dossier du compte")):
            m = re.search(rf'^\s*{cle}:\s*(\d{{4}}-\d\d-\d\d \d\d:\d\d:\d\d)', c.texte(f), re.M)
            if m:
                fait("compte", quoi, compte, c.rel(f), f"champ {cle} de stat",
                     horodatage=m.group(1).replace(" ", "T"), acteur=compte,
                     fuseau="poste d'analyse",
                     note="lu par le poste d'analyse, dans son fuseau")
    v = c.un("_disques_virtuels.txt", "MACHINES")
    for l in (c.texte(v).splitlines() if v else []):
        if l.strip():
            fait("suspect", "disque de machine virtuelle sur le poste", l.strip(),
                 c.rel(v), "find -iname '*.vmdk|*.vdi|*.ova|*.qcow2'",
                 confiance="à vérifier",
                 note="une machine virtuelle emporte son propre système : ce que "
                      "l'on y a fait n'est pas dans cette collecte")


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
    """Lit la sortie TEXTE de last. Rend le nombre de lignes retenues, pour
    savoir si le binaire manquait vraiment.

    Ce texte a été écrit par le poste d'analyse, dans SON fuseau, sans le
    dire : c'est une date de second rang. Le binaire wtmp, lui, porte l'epoch.
    On ne vient donc ici que quand le binaire manque, et chaque fait le dit.
    """
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
             horodatage=iso or g["debut"], acteur=acteur, confiance="forte",
             fuseau="poste d'analyse",
             note=note + " — heure écrite par le poste d'analyse dans son fuseau, "
                         "le binaire wtmp manquant",
             tty=g["tty"] or None, origine=depuis if depuis not in ("", "-") else None,
             fin=(lire_date(g["fin"]) or g["fin"]) if g.get("fin") else None)
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
             note=note or None, tty=e["tty"] or None, origine=e["ou"] or None)
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
        # wtmpdb compte en MICROsecondes, lastlog2 en secondes : l'unité est
        # celle de la table, pas une devinette sur la grandeur du nombre
        for nom_table, lignes in _sqlite_lire(blob, [
                ("wtmp", "SELECT User, Login, Logout, TTY, RemoteHost FROM wtmp"),
                ("lastlog2", "SELECT Name, Time, TTY, RemoteHost FROM Lastlog2")]):
            diviseur = 1_000_000 if nom_table == "wtmp" else 1
            for l in lignes:
                l = list(l) + [None] * 5
                qui, quand = l[0], l[1]
                iso = _epoch_iso(quand / diviseur) if isinstance(quand, (int, float)) and quand else None
                if nom_table == "wtmp":
                    tty, origine, fin = l[3], l[4], l[2]
                else:
                    tty, origine, fin = l[2], l[3], None
                detail = f"tty {tty}" if tty else ""
                if origine:
                    detail += f", depuis {origine}"
                fait("evenement",
                     "ouverture de session" if nom_table == "wtmp"
                     else "dernière connexion du compte",
                     qui, c.rel(chemin), f"sqlite3 sur la table {nom_table} de {base}",
                     horodatage=iso, acteur=qui, note=detail or None,
                     tty=tty or None, origine=origine or None,
                     fin=_epoch_iso(fin / diviseur) if isinstance(fin, (int, float)) and fin else None)


def sessions(c):
    """Le binaire wtmp d'abord : il porte l'epoch, donc l'heure exacte, et il
    contient aussi les démarrages et les arrêts. La sortie texte de last ne
    sert que s'il manque."""
    if not _utmp_brut(c, "wtmp", "evenement", "ouverture de session"):
        _last(c, c.un("_sessions.txt", "CONNEXIONS"), "evenement",
              "ouverture de session", "last -F -f wtmp")
        _last(c, c.un("_reboots.txt", "CONNEXIONS"), "evenement",
              "démarrage ou arrêt de la machine", "last -F -x -f wtmp reboot shutdown")
    if not _utmp_brut(c, "btmp", "evenement", "échec d'authentification"):
        _last(c, c.un("_echecs.txt", "CONNEXIONS"), "evenement",
              "échec d'authentification", "lastb -F -f btmp")
    _bases_connexion(c)

    # lastlog n'a pas de forme texte dans la collecte : il se lit ici ou nulle
    # part. Les uid viennent du passwd emporté à côté.
    _dates_dossiers(c)

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
# (catégorie, fait, littéral, motif, ce qu'on en tire). Le littéral est un
# mot que la ligne DOIT contenir : un « in » sur la ligne coûte cent fois
# moins que l'expression, et un journal fait des millions de lignes.
MOTIFS_JOURNAL = [
    ("evenement", "connexion SSH acceptée", 'Accepted',
     re.compile(r'sshd.*Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)'),
     lambda m: (m.group(2), f"depuis {m.group(3)} par {m.group(1)}", {"origine": m.group(3)})),
    ("evenement", "échec SSH", 'Failed',
     re.compile(r'sshd.*Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)'),
     lambda m: (m.group(1), f"depuis {m.group(2)}")),
    ("evenement", "commande sudo", 'COMMAND=',
     re.compile(r'sudo(?:\[\d+\])?:\s+(\S+)\s*:.*COMMAND=(.+)$'),
     lambda m: (m.group(1), f"a lancé {m.group(2).strip()}")),
    ("evenement", "changement d'utilisateur (su)", 'session opened',
     re.compile(r"\bsu(?:\[\d+\])?:.*session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]+)"),
     lambda m: (m.group(2), f"est devenu {m.group(1)}", {"cible": m.group(1)})),
    ("support", "support amovible USB branché", 'New USB device',
     re.compile(r'usb\s+([\d.-]+):\s+New USB device found,\s*(.*)$'),
     lambda m: (None, f"port {m.group(1)}, {m.group(2).strip()}")),
    # Le numéro de série est LA pièce d'identité du support : c'est lui qui
    # permet de dire que la même clé a servi sur une autre machine. Il ne doit
    # pas partager son étiquette avec le modèle.
    ("support", "numéro de série du support USB", 'SerialNumber',
     re.compile(r'usb\s+[\d.-]+:\s+SerialNumber:\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "modèle du support USB", 'Product:',
     re.compile(r'usb\s+[\d.-]+:\s+Product:\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "fabricant du support USB", 'Manufacturer:',
     re.compile(r'usb\s+[\d.-]+:\s+Manufacturer:\s*(.+)$'),
     lambda m: (None, m.group(1).strip())),
    ("support", "support USB débranché", 'USB disconnect',
     re.compile(r'usb\s+([\d.-]+):\s+USB disconnect, device number (\d+)'),
     lambda m: (None, f"port {m.group(1)}, appareil {m.group(2)}")),
    ("support", "support reconnu par SCSI", 'Direct-Access',
     re.compile(r'scsi\s+[\d:]+:\s+Direct-Access\s+(.+?)\s+PQ:'),
     lambda m: (None, re.sub(r'\s{2,}', " ", m.group(1).strip()))),
    ("support", "disque amovible reconnu", 'Attached SCSI',
     re.compile(r'\[(sd[a-z]+)\]\s+Attached SCSI removable disk'),
     lambda m: (None, f"/dev/{m.group(1)}")),
    # .*? et non .* : glouton, il partirait du « /media » de « /run/media ».
    # Le compte est dans le chemin — c'est l'attribution la plus directe qui
    # existe pour un support amovible.
    ("support", "système de fichiers amovible monté", '/media/',
     re.compile(r'(?:mount|gvfs|udisks).*?((?:/run)?/media/([^/\s]+)/\S*)'),
     lambda m: (m.group(2), m.group(1))),
    ("support", "montage demandé par un compte", 'on behalf of',
     re.compile(r'on behalf of uid (\d+)'),
     lambda m: (None, f"uid {m.group(1)}")),
    ("machine", "modèle de la machine (DMI du BIOS)", 'DMI:',
     re.compile(r'DMI:\s+(.+?),\s*BIOS\s+(.+)$'),
     lambda m: (None, f"{m.group(1).strip()} — BIOS {m.group(2).strip()}")),
    ("reseau", "adresse obtenue en DHCP", None,
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


def journal(source_rel, contenu, methode, fin_fichier=None):
    for ligne in contenu.splitlines():
        ts, reste, devine = _ligne_journal(ligne, fin_fichier)
        for categorie, quoi, litteral, motif, tire in MOTIFS_JOURNAL:
            if litteral and litteral not in reste:
                continue
            m = motif.search(reste)
            if not m:
                continue
            acteur, detail, *champs = tire(m)
            fait(categorie, quoi, detail, source_rel, methode,
                 horodatage=ts, acteur=acteur,
                 confiance="forte" if devine else "certaine",
                 note="année déduite de la date du fichier : la ligne syslog "
                      "ne la porte pas" if devine else
                      (None if ts else "ligne sans date exploitable"),
                 **(champs[0] if champs else {}))
            break


def journaux(c):
    j = c.un("_journal.txt", "JOURNAUX")
    if j:
        journal(c.rel(j), c.texte(j, 400_000_000),
                "journalctl -D var/log/journal -o short-iso, puis motifs")
    tarlog = c.un("_var_log.tar.gz", "JOURNAUX")
    if tarlog:
        for nom, blob in c.membres_tar(tarlog, _garde_journaux):
            quand = c.mtimes[tarlog].get(nom)
            _journal_brut(f"{c.rel(tarlog)} → {nom}", nom, blob, "tar -xO, puis motifs",
                          datetime.fromtimestamp(quand, timezone.utc) if quand else None)
    # Une pièce reprise à la main — un auth.log recopié depuis l'image, un
    # secure.3.gz — se pose telle quelle dans JOURNAUX/ : elle est lue comme
    # si la collecte l'avait emportée.
    dossier = os.path.join(c.racine, "JOURNAUX")
    if os.path.isdir(dossier):
        for base in sorted(os.listdir(dossier)):
            chemin = os.path.join(dossier, base)
            if not os.path.isfile(chemin) or base.endswith((".tar.gz", "_journal.txt")):
                continue
            with open(chemin, "rb") as fh:
                blob = fh.read()
            c.lus.add(chemin)
            _journal_brut(c.rel(chemin), base, blob,
                          "fichier posé à la main dans JOURNAUX/, puis motifs",
                          datetime.fromtimestamp(os.path.getmtime(chemin), timezone.utc))


JOURNAUX_LUS = ("secure", "auth.log", "messages", "syslog", "dmesg",
                "boot.log", "cron", "audit", "maillog", "yum.log")


def _garde_journaux(nom):
    return os.path.basename(nom).startswith(JOURNAUX_LUS)


def texte_de(nom, blob, source=None):
    """Le texte d'un membre d'archive, ou None s'il n'en est pas un :
    décompressé s'il le faut, écarté s'il est binaire. Un journal tourné
    qu'on ne sait pas décompresser laisse un fait « limite »."""
    if nom.endswith((".gz", ".xz", ".lzma", ".bz2", ".zst")):
        blob = decomprimer(nom, blob)
        if blob is None:
            fait("limite", "journal tourné non décompressé", nom, source or nom,
                 "compresseur non disponible", confiance="à vérifier",
                 note="son contenu n'est PAS dans l'analyse")
            return None
    if b"\x00" in blob[:4096]:
        return None                  # un journal binaire (systemd) n'est pas du texte
    return blob.decode("utf-8", "replace")


def _journal_brut(source, nom, blob, methode, fin):
    txt = texte_de(nom, blob, source)
    if txt is not None:
        journal(source, txt, methode, fin)


# ── 5 · réseau ────────────────────────────────────────────────────────
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


RESEAU_LUS = ("resolv.conf", "hosts", "known_hosts")


def _garde_reseau(nom):
    base = os.path.basename(nom)
    return (garde_sans_fil(nom) or base in RESEAU_LUS or base.startswith("ifcfg-")
            or base.endswith((".nmconnection", ".lease", ".leases")))


def reseau(c):
    t = c.un("_reseau.tar.gz", "RESEAU")
    if not t:
        return
    for nom, blob in c.membres_tar(t, _garde_reseau):
        txt = blob.decode("utf-8", "replace")
        base = os.path.basename(nom)
        for ssid, methode in ssids_de(nom, txt):
            fait("reseau", "réseau sans fil enregistré", ssid, f"{c.rel(t)} → {nom}", methode,
                 note="la machine connaît ce réseau ; seul NetworkManager date la "
                      "dernière association (var/lib/NetworkManager/timestamps)")
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
        elif base.startswith("ifcfg-"):
            champs = _champs(txt)
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
@contextlib.contextmanager
def _sqlite(blob):
    """Une base sqlite copiée hors des scellés, ouverte immuable : rien n'est
    jamais écrit dans la pièce, pas même un journal -wal."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(blob)
        tmp.flush()
        try:
            cx = sqlite3.connect(f"file:{tmp.name}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error:
            yield None
            return
        try:
            yield cx
        finally:
            cx.close()


def _lignes(cx, sql, params=()):
    if cx is None:
        return []
    try:
        return cx.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []


def _sqlite_lire(blob, requetes):
    """(nom, lignes) pour chaque requête d'une même base."""
    with _sqlite(blob) as cx:
        for nom, sql in requetes:
            lignes = _lignes(cx, sql)
            if lignes:
                yield nom, lignes


# Les visites sont bornées, et la borne est un fait : quand elle est atteinte,
# un fait « limite » dit combien de pages restent hors des faits. Un profil
# de plusieurs années en compte des dizaines de milliers ; la borne se règle
# par --visites. Chaque page porte son nombre de visites et la première : ce
# qui distingue un passage d'une habitude.
FF_EPOCH = "datetime(v.last_visit_date/1000000,'unixepoch')"
REQ_FIREFOX = {
    "total": "SELECT COUNT(*) FROM moz_places WHERE last_visit_date IS NOT NULL",
    "visite": f"SELECT {FF_EPOCH}, v.url, v.title, v.visit_count, "
              "(SELECT datetime(MIN(h.visit_date)/1000000,'unixepoch') "
              " FROM moz_historyvisits h WHERE h.place_id=v.id) "
              "FROM moz_places v WHERE v.last_visit_date IS NOT NULL "
              "ORDER BY v.last_visit_date DESC LIMIT ?",
    "telechargement":
        "SELECT datetime(a.dateAdded/1000000,'unixepoch'), a.content, p.url "
        "FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
        "WHERE a.content LIKE 'file://%' ORDER BY a.dateAdded DESC LIMIT ?",
    # un marque-page est un choix délibéré, et il est DATÉ : il survit au
    # vidage de l'historique, que l'utilisateur croit souvent suffisant
    "marque-page":
        "SELECT datetime(b.dateAdded/1000000,'unixepoch'), p.url, b.title "
        "FROM moz_bookmarks b JOIN moz_places p ON p.id=b.fk "
        "WHERE b.type=1 AND p.url NOT LIKE 'place:%' "
        "ORDER BY b.dateAdded DESC LIMIT ?",
}
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

REQ_CHROME = {
    "total": "SELECT COUNT(*) FROM urls WHERE last_visit_time > 0",
    "visite": "SELECT datetime(u.last_visit_time/1000000-11644473600,'unixepoch'), "
              "u.url, u.title, u.visit_count, "
              "(SELECT datetime(MIN(x.visit_time)/1000000-11644473600,'unixepoch') "
              " FROM visits x WHERE x.url=u.id) "
              "FROM urls u WHERE u.last_visit_time > 0 "
              "ORDER BY u.last_visit_time DESC LIMIT ?",
    "telechargement":
        "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url "
        "FROM downloads ORDER BY start_time DESC LIMIT ?",
    # ce que le compte a TAPÉ dans la barre d'adresse : l'intention, pas
    # seulement la page atteinte
    "recherche":
        "SELECT datetime(u.last_visit_time/1000000-11644473600,'unixepoch'), k.term, u.url "
        "FROM keyword_search_terms k JOIN urls u ON u.id=k.url_id "
        "ORDER BY u.last_visit_time DESC LIMIT ?",
}

# Les mots de passe enregistrés : on lit le SITE, jamais l'identifiant ni le
# secret. Que « intranet.example » ait un mot de passe enregistré dans Firefox
# est un fait utile (une charte l'interdit souvent) ; le nom d'utilisateur
# n'ajoute rien au fait, et le mot de passe est chiffré de toute façon.
REQ_LOGINS_CHROME = [
    ("identifiant", "SELECT origin_url, date_created, date_last_used FROM logins"),
]

# Le fichier, le navigateur, ce qu'on en fait. C'est LA liste des bases de
# navigateur : la garde des fichiers -wal s'y réfère aussi.



def _iso_z(ts):
    """« 2025-12-19 12:40:00 » de sqlite → « 2025-12-19T12:40:00Z » : c'est de l'UTC."""
    return ts.replace(" ", "T") + "Z" if isinstance(ts, str) and len(ts) == 19 else ts


def _date_us(v, depuis_1601=False):
    """Microsecondes en ISO. Firefox compte depuis 1970, Chrome depuis 1601."""
    if not isinstance(v, (int, float)) or not v:
        return None
    sec = v / 1_000_000 - (11_644_473_600 if depuis_1601 else 0)
    try:
        return _epoch_iso(sec)
    except (OSError, OverflowError, ValueError):
        return None


def _cookies(source, compte, blob, requetes, outil, depuis_1601):
    for _, lignes in _sqlite_lire(blob, requetes):
        for hote, combien, cree, vu in lignes:
            fait("navigation", "domaine ayant posé un cookie", hote, source,
                 f"sqlite3 sur les cookies {outil}, regroupé par domaine "
                 "(la valeur du cookie n'est pas lue)",
                 horodatage=_date_us(vu, depuis_1601), acteur=compte,
                 note=f"{combien} cookie(s), premier posé le "
                      f"{_date_us(cree, depuis_1601)} — un cookie subsiste "
                      "quand l'historique a été vidé")
        return                          # le premier schéma qui répond suffit


def _logins_firefox(source, compte, blob, req, outil):
    """Les sites pour lesquels un mot de passe est enregistré. Le site seul."""
    try:
        entrees = json.loads(blob.decode("utf-8", "replace")).get("logins", [])
    except (ValueError, AttributeError):
        return
    for e in entrees:
        if isinstance(e, dict) and e.get("hostname"):
            cree, vu = e.get("timeCreated"), e.get("timeLastUsed")
            fait("usage", "mot de passe enregistré dans le navigateur", e["hostname"],
                 source, "champ hostname de logins.json (identifiant et mot de passe non lus)",
                 horodatage=_date_us(vu * 1000) if vu else None, acteur=compte,
                 note=f"enregistré le {_date_us(cree * 1000)}" if cree else None)


def _logins_chrome(source, compte, blob, req, outil):
    for _, lignes in _sqlite_lire(blob, req):
        for site, cree, vu in lignes:
            fait("usage", "mot de passe enregistré dans le navigateur", site, source,
                 "colonne origin_url de la table logins (identifiant et mot de passe non lus)",
                 horodatage=_date_us(vu, True), acteur=compte,
                 note=f"enregistré le {_date_us(cree, True)}" if cree else None)


def _historique_navigateur(source, compte, blob, req, outil, limite):
    with _sqlite(blob) as cx:
        total = (_lignes(cx, req["total"]) or [[None]])[0][0]
        visites = _lignes(cx, req["visite"], (limite,))
        for ts, url, titre, combien, premiere in visites:
            ts, premiere = _iso_z(ts), _iso_z(premiere)
            note = f"{combien} visite(s)" if combien else ""
            if premiere and premiere != ts:
                note += f", la première le {premiere}"
            if titre:
                note = f"{note} — {titre}" if note else titre
            fait("navigation", "page visitée", url, source,
                 f"sqlite3 sur l'historique {outil}", horodatage=ts, acteur=compte,
                 note=note or None)
        for ts, cible, origine in _lignes(cx, req["telechargement"], (limite,)):
            fait("telechargement", "fichier téléchargé", cible, source,
                 f"sqlite3 sur les téléchargements {outil}", horodatage=_iso_z(ts),
                 acteur=compte, note=f"depuis {origine}" if origine else None)
        signets = _lignes(cx, req["marque-page"], (limite,)) if req.get("marque-page") else []
        for ts, url, titre in signets:
            fait("navigation", "marque-page enregistré", url, source,
                 f"sqlite3 sur les marque-pages {outil}", horodatage=_iso_z(ts),
                 acteur=compte, note=(titre or None),
                 confiance="certaine")
        _borne_atteinte(len(signets), limite, "marque-pages", source, compte,
                        f"LIMIT {limite} sur les marque-pages {outil}")
        for ts, terme, url in _lignes(cx, req.get("recherche", ""), (limite,)) if req.get("recherche") else []:
            fait("navigation", "recherche saisie dans la barre d'adresse", terme, source,
                 f"sqlite3 sur keyword_search_terms {outil}", horodatage=_iso_z(ts),
                 acteur=compte, confiance="forte",
                 note=(f"a mené à {url}. " if url else "")
                      + "la date est celle de la DERNIÈRE visite de la page atteinte, "
                        "pas celle de la frappe : une recherche ancienne dont la page a "
                        "été revue porte la date récente")
    if total and total > len(visites):
        fait("limite", "historique de navigation tronqué",
             f"{len(visites)} pages sur {total}", source,
             f"COUNT(*) sur l'historique {outil}, borne --visites {limite}",
             acteur=compte, confiance="certaine",
             note="les pages les plus anciennes ne sont pas dans les faits ; "
                  "relancez avec --visites plus grand pour les avoir")


def _recemment_ouverts(source, compte, blob, req, outil):
    for m2 in re.finditer(r'href="([^"]+)"[^>]*(?:added|modified)="([^"]+)"',
                          blob.decode("utf-8", "replace")):
        fait("usage", "fichier ouvert récemment", m2.group(1), source,
             "grep href= recently-used.xbel", horodatage=m2.group(2), acteur=compte)


# Ce que le compte a SAISI dans une page : recherches, identifiants de
# connexion (le nom, jamais le mot de passe — il n'est pas là), adresses.
# C'est l'intention, là où l'historique ne donne que le résultat.
REQ_FORMULAIRES_FF = [
    ("formulaire", "SELECT fieldname, value, timesUsed, "
                   "datetime(firstUsed/1000000,'unixepoch'), datetime(lastUsed/1000000,'unixepoch') "
                   "FROM moz_formhistory ORDER BY lastUsed DESC LIMIT 500"),
]
# Chrome compte en SECONDES dans cette table — pas en microsecondes comme
# ailleurs : c'est la table, pas une devinette.
REQ_FORMULAIRES_CHROME = [
    ("formulaire", "SELECT name, value, count, "
                   "datetime(date_created,'unixepoch'), datetime(date_last_used,'unixepoch') "
                   "FROM autofill ORDER BY date_last_used DESC LIMIT 500"),
]


def _borne_atteinte(rendues, borne, quoi, source, compte, methode):
    """Une requête qui rend exactement sa borne en cachait peut-être d'autres."""
    if rendues >= borne:
        fait("limite", f"{quoi} : la borne de lecture est atteinte", str(borne), source,
             methode, acteur=compte, confiance="à vérifier",
             note="il y en a peut-être davantage ; les plus anciens ne sont pas dans "
                  "les faits")


def _formulaires(source, compte, blob, req, outil):
    for _, lignes in _sqlite_lire(blob, req):
        _borne_atteinte(len(lignes), 500, "saisies de formulaire", source, compte,
                        f"LIMIT 500 sur l'historique de formulaires {outil}")
        for champ, valeur, combien, premier, dernier in lignes:
            fait("usage", "saisie dans un formulaire", str(valeur)[:200], source,
                 f"sqlite3 sur l'historique de formulaires {outil}",
                 horodatage=_iso_z(dernier), acteur=compte,
                 note=f"champ « {champ} », {combien} fois, la première le {_iso_z(premier)}"
                      " — ce que le compte a tapé, pas ce qu'il a atteint")
        return


def _marque_pages_chrome(source, compte, blob, req, outil):
    """Chrome garde ses marque-pages en JSON, avec la date en microsecondes
    depuis 1601 comme le reste de ses bases."""
    try:
        racines = json.loads(blob.decode("utf-8", "replace")).get("roots", {})
    except (ValueError, AttributeError):
        return
    pile = [(v, k) for k, v in racines.items() if isinstance(v, dict)]
    poses, borne = 0, 2000
    while pile and poses < borne:
        noeud, dossier = pile.pop()
        for enfant in noeud.get("children", []) or []:
            if enfant.get("type") == "folder":
                pile.append((enfant, enfant.get("name") or dossier))
            elif enfant.get("url"):
                poses += 1
                quand = enfant.get("date_added")
                fait("navigation", "marque-page enregistré", enfant["url"], source,
                     "lecture du fichier Bookmarks (JSON)", acteur=compte,
                     horodatage=_date_us(int(quand), True) if str(quand).isdigit() else None,
                     note=f"« {enfant.get('name', '')} », dans « {dossier} »")
    _borne_atteinte(poses, borne, "marque-pages", source, compte,
                    f"borne de {borne} marque-pages dans le fichier Bookmarks")


# Le fichier, le navigateur, la requête, le traitement. C'est LA liste des
# bases de navigateur : la garde des fichiers -wal s'y réfère aussi.
NAVIGATEURS = {
    "places.sqlite": ("Firefox", REQ_FIREFOX, "historique"),
    "History": ("Chromium/Chrome", REQ_CHROME, "historique"),
    "cookies.sqlite": ("Firefox (moz_cookies)", REQ_COOKIES_FF, "cookies"),
    "Cookies": ("Chromium/Chrome", REQ_COOKIES_CHROME, "cookies"),
    "logins.json": ("Firefox", None, _logins_firefox),
    "Login Data": ("Chromium/Chrome", REQ_LOGINS_CHROME, _logins_chrome),
    "recently-used.xbel": ("bureau", None, _recemment_ouverts),
    "Bookmarks": ("Chromium/Chrome", None, _marque_pages_chrome),
    "formhistory.sqlite": ("Firefox", REQ_FORMULAIRES_FF, _formulaires),
    "Web Data": ("Chromium/Chrome", REQ_FORMULAIRES_CHROME, _formulaires),
}


def _base_navigateur(source, compte, base, blob, visites):
    """Un membre d'archive dont le nom est dans NAVIGATEURS — ou son -wal."""
    if base in NAVIGATEURS:
        outil, req, traitement = NAVIGATEURS[base]
        if traitement == "historique":
            _historique_navigateur(source, compte, blob, req, outil, visites)
        elif traitement == "cookies":
            _cookies(source, compte, blob, req, outil, base == "Cookies")
        else:
            traitement(source, compte, blob, req, outil)
    elif len(blob) > 32:                            # un -wal ou -journal non vide
        fait("limite", "base de navigateur copiée à chaud", source.split(" → ")[-1], source,
             "présence d'un fichier -wal non vide", acteur=compte, confiance="à vérifier",
             note="les visites les plus récentes sont dans ce journal, pas dans la "
                  "base : elles manquent à l'analyse")


def _garde_navigation(nom):
    base = os.path.basename(nom)
    return (base in NAVIGATEURS or base.removesuffix("-wal").removesuffix("-journal") in NAVIGATEURS
            or (base == "prefs.js" and "thunderbird" in nom.lower()))


def _applications(c, prof, compte):
    """Les applications snap et flatpak d'un compte, par le nom des membres de
    l'archive : ~/snap/<application>/ et ~/.var/app/<identifiant>/.

    Elles échappent à dpkg et à rpm — un poste peut porter Steam ou un client
    torrent sans qu'aucune liste de paquets ne le dise. Aucune lecture de plus :
    les noms ont été relevés au passage de l'archive.
    """
    vus = set()
    for nom in c.mtimes.get(prof, ()):
        ch = nom.split("/")
        if len(ch) > 2 and ch[0] == "snap" and ch[1] not in vus:
            vus.add(ch[1])
            fait("paquet", "application snap présente chez ce compte", ch[1],
                 f"{c.rel(prof)} → snap/{ch[1]}/", "noms des dossiers de ~/snap",
                 acteur=compte, confiance="forte",
                 note="un snap n'apparaît ni dans dpkg ni dans rpm")
        elif len(ch) > 3 and (ch[0], ch[1]) == (".var", "app") and ch[2] not in vus:
            vus.add(ch[2])
            fait("paquet", "application flatpak présente chez ce compte", ch[2],
                 f"{c.rel(prof)} → .var/app/{ch[2]}/", "noms des dossiers de ~/.var/app",
                 acteur=compte, confiance="forte",
                 note="un flatpak n'apparaît ni dans dpkg ni dans rpm")


RE_TB_COURRIEL = re.compile(r'user_pref\("mail\.identity\.id\d+\.useremail",\s*"([^"]+)"')
RE_TB_SERVEUR = re.compile(r'user_pref\("mail\.server\.server\d+\.hostname",\s*"([^"]+)"')


def _thunderbird(source, compte, blob, req, outil):
    txt = blob.decode("utf-8", "replace")
    for motif, quoi in ((RE_TB_COURRIEL, "adresse de courriel configurée"),
                        (RE_TB_SERVEUR, "serveur de courriel configuré")):
        for v in dict.fromkeys(m.group(1) for m in motif.finditer(txt)):
            fait("reseau" if "serveur" in quoi else "compte", quoi, v, source,
                 "user_pref de prefs.js (Thunderbird)", acteur=compte, confiance="forte",
                 note="configuration du client de courriel de ce compte")


def navigation(c):
    """Les navigateurs. Ils vivent dans DEUX archives, et l'oublier fait
    manquer un navigateur entier : Firefox est dans ~/.mozilla, donc dans
    _profils ; Chrome ou Chromium installés par paquet sont dans ~/.config,
    donc dans _artefacts. Chromium en snap est dans ~/snap : _profils.

    Les artefacts portent aussi les historiques, les clés, les hôtes connus :
    la même passe les donne à persistance(), pour ne lire l'archive qu'une fois.
    """
    for suffixe in ("_profils.tar.gz", "_artefacts.tar.gz"):
        for prof in c.chercher(suffixe, "COMPTES"):
            compte = _compte_de(prof, suffixe[1:])
            for nom, blob in c.membres_tar(prof, lambda n: _garde_navigation(n) or _garde_artefacts(n)):
                if os.path.basename(nom) == "prefs.js" and "thunderbird" in nom.lower():
                    _thunderbird(f"{c.rel(prof)} → {nom}", compte, blob, None, None)
                    continue
                base = os.path.basename(nom)
                source = f"{c.rel(prof)} → {nom}"
                if _garde_navigation(nom):
                    _base_navigateur(source, compte, base, blob, c.visites)
                else:
                    _artefact(source, compte, base, blob)
            _applications(c, prof, compte)


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


ARTEFACTS_LUS = ("_history", ".lesshst", ".wget-hsts", "known_hosts", ".viminfo",
                 "authorized_keys", ".desktop")
# Ce qui lance un programme depuis un endroit qu'un paquet n'utilise jamais :
# le classique de la persistance, et ce qui mérite d'être lu en premier.
LIEU_ANORMAL = re.compile(r'(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/|curl\s|wget\s|base64|\bnc\s|/\.[\w.]+/)')
RE_EXEC = re.compile(r'^\s*(?:ExecStart|ExecStartPre|Exec)\s*=\s*(.+)$', re.M)
RE_RUN_UDEV = re.compile(r'^(?!\s*#).*?\bRUN(?:\{\w+\})?\s*\+?=\s*"?([^"\n]+?)"?\s*$', re.M)
RE_HISTO_EPOCH = re.compile(r'^#(\d{9,11})$')
RE_CLE_PACMAN = re.compile(r'^%([A-Z]+)%\n(.+)$', re.M)
RE_HISTO_ZSH = re.compile(r'^: (\d{9,11}):\d+;(.*)$')


def _persistance_lance(c, t, nom, txt, vendeur):
    """Ce qu'une unité systemd, un autostart ou une règle udev fait démarrer.

    Un poste porte deux cents unités livrées par ses paquets : les compter
    suffit. Celles que l'administrateur a posées (etc/systemd/system) et
    celles qui lancent quelque chose depuis un endroit anormal se citent, une
    par une.
    """
    source = f"{c.rel(t)} → {nom}"
    if nom.endswith((".service", ".timer", ".socket", ".path")):
        # tout ce qui vient de /etc a été posé à la main ou par un installeur —
        # y compris les unités « user » ; les paquets écrivent dans /usr
        pose_main = "/etc/systemd/" in "/" + nom
        commandes = [m.group(1).strip() for m in RE_EXEC.finditer(txt)]
        if not (pose_main or any(LIEU_ANORMAL.search(x) for x in commandes)):
            vendeur[0] += 1                       # une unité, pas un ExecStart
            return
        for commande in commandes:
            anormal = LIEU_ANORMAL.search(commande)
            fait("suspect" if anormal else "persistance",
                 "unité systemd lançant un programme depuis un endroit anormal"
                 if anormal else "unité systemd posée par l'administrateur",
                 f"{os.path.basename(nom)} : {commande[:140]}", source,
                 "ExecStart= de l'unité systemd",
                 confiance="à vérifier" if anormal else "certaine",
                 note="une unité livrée par un paquet lance depuis /usr ; "
                      "celle-ci ne le fait pas" if anormal else
                      "posée à la main ou par un installeur, pas par le gestionnaire "
                      "de paquets")
    elif nom.endswith(".desktop") and "autostart" in nom:
        for m in re.finditer(r'^\s*Exec\s*=\s*(.+)$', txt, re.M):
            fait("persistance", "programme lancé à l'ouverture de session",
                 f"{os.path.basename(nom)} : {m.group(1).strip()[:140]}", source,
                 "Exec= du fichier .desktop d'autostart", confiance="certaine")
    elif nom.endswith(".rules") and "udev" in nom:
        for m in RE_RUN_UDEV.finditer(txt):
            fait("persistance", "règle udev lançant un programme",
                 f"{os.path.basename(nom)} : {m.group(1).strip()[:140]}", source,
                 "RUN+= d'une règle udev", confiance="à vérifier",
                 note="se déclenche au branchement d'un matériel")
    elif os.path.basename(nom) in ("rc.local",) or "/profile.d/" in nom:
        for l in txt.splitlines():
            l = l.strip()
            if l and not l.startswith("#") and LIEU_ANORMAL.search(l):
                fait("suspect", "commande lancée au démarrage depuis un endroit anormal",
                     f"{os.path.basename(nom)} : {l[:140]}", source,
                     "lignes de rc.local ou profile.d", confiance="à vérifier")


def persistance(c):
    t = c.un("_persistance.tar.gz", "PERSISTANCE")
    vendeur = [0]
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
            _persistance_lance(c, t, nom, txt, vendeur)
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
    if vendeur[0]:
        fait("persistance", "unités systemd livrées par des paquets (nombre)",
             str(vendeur[0]), c.rel(t), "unités lançant depuis un chemin ordinaire",
             note="comptées, pas listées : elles viennent du gestionnaire de paquets, "
                  "et il y en a deux cents sur un poste ordinaire")



def _garde_artefacts(nom):
    return (os.path.basename(nom).endswith(ARTEFACTS_LUS)
            and (not nom.endswith(".desktop") or "autostart/" in nom))


def _lignes_historique(txt):
    """[(commande, date)] d'un historique : bash date par une ligne « #<epoch> »
    avant chaque commande quand HISTTIMEFORMAT était posé ; zsh étendu écrit
    « : epoch:0;cmd ». Sans cela la date est None."""
    lignes, quand = [], None
    for l in txt.splitlines():
        m = RE_HISTO_EPOCH.match(l)
        if m:
            quand = _epoch_iso(int(m.group(1)))
            continue
        m = RE_HISTO_ZSH.match(l)
        if m:
            lignes.append((m.group(2), _epoch_iso(int(m.group(1)))))
            continue
        if l.strip() and not l.startswith("#"):
            lignes.append((l, quand))
            quand = None
    return lignes


def _artefact(source, compte, base, blob):
    """Un membre de _artefacts.tar.gz retenu par ARTEFACTS_LUS."""
    txt = blob.decode("utf-8", "replace")
    if base.endswith(("_history", ".lesshst", ".wget-hsts")):
        lignes = _lignes_historique(txt)
        dates = sorted(d for _, d in lignes if d)
        # bash n'écrit de dates que si HISTTIMEFORMAT était posé. Sans elles,
        # l'historique n'est PAS datable — c'est un fait à dire.
        if dates:
            fait("usage", "historique daté (HISTTIMEFORMAT posé)",
                 f"{len(lignes)} commandes, {len(dates)} datées", source,
                 "comptage des lignes « #<epoch> » de l'historique",
                 acteur=compte, horodatage=dates[-1], note=f"de {dates[0]} à {dates[-1]}")
        else:
            fait("usage", "historique NON daté", f"{len(lignes)} commandes", source,
                 "absence de lignes « #<epoch> » dans l'historique",
                 acteur=compte, confiance="certaine",
                 note="aucune date dans le fichier : ne datez aucune de ces "
                      "commandes sans une autre source")
        for l, quand in lignes:
            for motif, quoi in SUSPECT:
                if motif.search(l):
                    fait("suspect", quoi, l.strip(), source,
                         f"motif « {motif.pattern} » dans l'historique",
                         acteur=compte, horodatage=quand, confiance="à vérifier",
                         note=None if quand else "commande non datée : sa position "
                                                 "dans le fichier ne prouve pas son moment")
                    break
    elif base == "known_hosts":
        for l in txt.splitlines():
            if not l.strip() or l.startswith("#"):
                continue
            hote = l.split()[0]
            hache = hote.startswith("|1|")
            fait("reseau", "hôte SSH contacté depuis ce compte",
                 "empreinte masquée" if hache else hote, source,
                 "cut -d' ' -f1 .ssh/known_hosts", acteur=compte,
                 confiance="à vérifier" if hache else "forte",
                 note="HashKnownHosts : le nom de l'hôte est illisible" if hache else None)
    elif base == ".viminfo":
        for m in re.finditer(r'^[:>]\s*e?\s*(/\S+)', txt, re.M):
            fait("usage", "fichier ouvert dans vim", m.group(1), source,
                 "grep des chemins dans .viminfo", acteur=compte,
                 note="viminfo garde le chemin même après suppression")
    elif base.endswith(".desktop"):
        for m in re.finditer(r'^\s*Exec\s*=\s*(.+)$', txt, re.M):
            fait("persistance", "programme lancé à l'ouverture de session de ce compte",
                 f"{base} : {m.group(1).strip()[:140]}", source,
                 "Exec= d'un .desktop de ~/.config/autostart", acteur=compte,
                 confiance="certaine",
                 note="propre à ce compte : il se lance quand il ouvre sa session")
    elif base == "authorized_keys" and txt.strip():
        for l in txt.splitlines():
            if l.strip() and not l.startswith("#"):
                fait("suspect", "clé SSH autorisée à ouvrir ce compte", l.strip()[:120],
                     source, "cat .ssh/authorized_keys", acteur=compte,
                     confiance="certaine", note="permet une entrée sans mot de passe")


RE_PACMAN = re.compile(r"^\[([^\]]+)\] \[(?:ALPM\] (installed|removed|upgraded) (\S+) \(([^)]*)\)"
                       r"|PACMAN\] Running '([^']+)')", re.M)
ACTIONS_PACMAN = {"installed": "paquet posé", "removed": "paquet retiré"}


def _commande_paquet(commande, source, methode, quand, acteur=None):
    fait("paquet", "commande du gestionnaire de paquets", commande, source, methode,
         horodatage=quand, acteur=acteur)


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
                    iso = _epoch_iso(quand) if isinstance(quand, (int, float)) and quand else None
                    _commande_paquet(ligne, f"{c.rel(t)} → {nom}",
                                     f"sqlite3 sur la table {table} de {base}", iso)
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
                    _commande_paquet(cmd.group(1).strip(), f"{c.rel(t)} → {nom}",
                                     "blocs Start-Date/Commandline de apt/history.log",
                                     f"{d.group(1)}T{d.group(2)}")
            continue
        # zypper : « date|commande|paquet|version|arch|qui|dépôt|somme » —
        # chaque pose datée, ce que rpm -qa --last ne donne plus quand la base
        # est au format ndb. pacman : « [date] [ALPM] installed x (v) ».
        if base == "history" and "zypp" in nom:
            # les commandes sont notées en commentaire : « # date|command|qui|'zypper' 'in' …| »
            lignes = [l.lstrip("# ").split("|") for l in txt.splitlines() if "|" in l]
            premiere = min((ch[0] for ch in lignes), default=None)
            if premiere:
                fait("machine", "installation du système (première ligne de zypp/history)",
                     premiere, f"{c.rel(t)} → {nom}", "première date de var/log/zypp/history",
                     horodatage=premiere.replace(" ", "T"), confiance="forte")
            for ch in lignes:
                if len(ch) < 4:
                    continue
                quand = ch[0].replace(" ", "T")
                if ch[1] in ("install", "remove"):
                    fait("paquet", "paquet retiré" if ch[1] == "remove" else "paquet posé",
                         f"{ch[2]} {ch[3]}", f"{c.rel(t)} → {nom}",
                         "colonnes de var/log/zypp/history", horodatage=quand,
                         note=f"par {ch[5]}" if len(ch) > 5 and ch[5] else None)
                elif ch[1] == "command":
                    _commande_paquet(ch[3].replace("' '", " ").strip("'"), f"{c.rel(t)} → {nom}",
                                     "lignes « command » de zypp/history", quand,
                                     acteur=ch[2].split("@")[0] or None)
            continue
        if base == "pacman.log":
            # un poste Arch met tout à jour chaque semaine : des milliers de
            # lignes « upgraded » sans intérêt une à une — elles se comptent
            maj = []
            for m in RE_PACMAN.finditer(txt):
                quand, action, paquet, version, commande = m.groups()
                if commande:
                    _commande_paquet(commande, f"{c.rel(t)} → {nom}",
                                     "lignes [PACMAN] Running de pacman.log", quand)
                elif action == "upgraded":
                    maj.append(quand)
                else:
                    fait("paquet", ACTIONS_PACMAN[action], f"{paquet} {version}",
                         f"{c.rel(t)} → {nom}", "lignes [ALPM] de var/log/pacman.log",
                         horodatage=quand)
            if maj:
                fait("paquet", "paquets mis à jour (nombre)", str(len(maj)),
                     f"{c.rel(t)} → {nom}", "lignes [ALPM] upgraded de pacman.log",
                     horodatage=maj[-1], note=f"du {maj[0]} au {maj[-1]} ; le détail est "
                                              "dans le fichier, ligne à ligne")
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


# Ce qu'un fichier récupéré peut être, quand son extension le dit. photorec
# rend un contenu sans nom ni date : le TYPE est tout ce qu'on a pour trier.
FAMILLES_RECUP = {
    "document": ("doc", "docx", "odt", "rtf", "pdf", "xls", "xlsx", "ods", "ppt", "pptx", "odp"),
    "image": ("jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "webp"),
    "archive": ("zip", "rar", "7z", "gz", "tar", "bz2", "xz"),
    "vidéo ou son": ("mp4", "mkv", "avi", "mov", "mp3", "wav", "flac", "webm"),
    "base ou courriel": ("sqlite", "db", "mbox", "pst", "eml", "msg"),
    "secret possible": ("key", "pem", "p12", "pfx", "kdbx", "ovpn", "gpg", "asc"),
    "exécutable ou script": ("exe", "dll", "elf", "sh", "ps1", "bat", "deb", "rpm"),
}
_TYPE_RECUP = {ext: fam for fam, exts in FAMILLES_RECUP.items() for ext in exts}


def _taille(octets):
    """Une taille qu'un lecteur comprend : « 975 Ko », pas « 0 Mo »."""
    for unite, seuil in (("Go", 1 << 30), ("Mo", 1 << 20), ("Ko", 1 << 10)):
        if octets >= seuil:
            return f"{octets / seuil:.1f} {unite}".replace(".0 ", " ")
    return f"{octets} octets"


def supprimes(c):
    for d in ("SUPPRIMES", "PHOTOREC"):
        base = os.path.join(c.racine, d)
        if not os.path.isdir(base):
            continue
        par_type, n, octets = collections.Counter(), 0, 0
        for dossier, _, fichiers in os.walk(base):
            for f in fichiers:
                n += 1
                ext = f.rsplit(".", 1)[-1].lower() if "." in f else ""
                par_type[_TYPE_RECUP.get(ext, f".{ext}" if ext else "sans extension")] += 1
                try:
                    octets += os.path.getsize(os.path.join(dossier, f))
                except OSError:
                    pass
        if not n:
            continue
        fait("recuperation", f"pièces récupérées dans {d}/", str(n), d + "/",
             "find | wc -l",
             note=f"{_taille(octets)} ; xfs_undelete rend des blocs entiers, "
                  "photorec coupe juste mais ignore ce dont il n'a pas la signature")
        for fam, combien in par_type.most_common(15):
            fait("recuperation", f"pièces récupérées de type « {fam} »", str(combien),
                 d + "/", "extension des fichiers rendus", confiance="forte",
                 note="photorec ne rend ni le nom ni la date d'origine : le type est "
                      "tout ce qui les trie. Cherchez-y une empreinte ou une chaîne "
                      "avec --indicateurs" if fam in ("document", "secret possible",
                                                       "base ou courriel") else None)


# Le genre n'est PAS figé sur les quatre connus : un extrait ajouté à
# collecte-linux.conf serait sinon ignoré en silence, sans fait ni limite pour
# le dire. Il ressort ici sous son nom brut, ce qui est honnête à défaut d'être
# élégant.
RE_EXTRAIT = re.compile(r'_strings_(?P<volume>.+)_(?P<genre>[a-z]+)\.txt$')
RE_BRUT = re.compile(r'_strings_(?P<volume>.+)\.txt\.gz$')
_GENRE_CHAINE = {
    "urls": "adresse web",
    "courriels": "adresse de courriel",
    "ip": "adresse IP",
    "chemins": "chemin personnel",
}
_SANS_DATE = ("lu sur les OCTETS du disque : ni date, ni fichier d'origine, ni "
              "compte. Une chaîne présente ici a existé sur ce volume, c'est tout "
              "ce qu'elle établit")


def chaines(c):
    """Les chaînes lisibles des PÉRIPHÉRIQUES, volume par volume.

    Ce que cette pièce a d'unique : elle est lue sur les octets du disque, pas
    sur les fichiers. Une adresse effacée du navigateur, un chemin de fichier
    supprimé, une IP qui n'est plus dans aucune configuration y sont encore —
    dans le slack, dans le swap, dans une page libérée. C'est la seule pièce
    qui répond à « cela a-t-il jamais existé sur ce disque ? » quand tout le
    reste a été vidé.

    En contrepartie, elle ne dit NI QUAND, NI DANS QUEL FICHIER, NI PAR QUI.
    Chaque fait le porte, pour qu'aucune ligne du rapport ne lui fasse dire
    plus qu'elle ne sait.
    """
    base = os.path.join(c.racine, "STRINGS")
    if not os.path.isdir(base):
        return
    for f in sorted(os.listdir(base)):
        chemin = os.path.join(base, f)
        brut = RE_BRUT.search(f)
        if brut:
            # Rapporté sur ses PROPRES preuves : un .gz dont les extraits
            # manquent est justement le cas qu'il faut signaler.
            fait("chaines", "chaînes brutes du périphérique", brut.group("volume"),
                 c.rel(chemin), "strings -a -t d -n 8 sur le périphérique",
                 note=f"{_taille(os.path.getsize(chemin))} compressés ; chaque ligne "
                      "porte son DÉCALAGE EN OCTETS sur le volume, ce qui permet de "
                      "revenir à l'emplacement exact. Cherchez-y avec --indicateurs")
            continue
        m = RE_EXTRAIT.search(f)
        if not m:
            continue
        volume, genre = m.group("volume"), m.group("genre")
        libelle = _GENRE_CHAINE.get(genre, genre)
        methode = f"strings sur le périphérique de {volume}, motif « {genre} »"
        # c.lignes et non c.texte : ce dernier coupe à 8 Mo SANS LE DIRE, et
        # l'extrait d'un vrai disque les dépasse — le nombre rapporté serait
        # alors celui des huit premiers mégaoctets, dans une pièce dont le
        # nombre est tout l'intérêt.
        # « <compte> <décalage> <chaîne> » : le décalage est celui de la
        # PREMIÈRE occurrence, et c'est lui qui permet de retrouver l'endroit
        # exact dans le .gz sans le rouvrir.
        tete, total = [], 0
        for l in c.lignes(chemin):
            ch = l.strip().split(None, 2)
            if len(ch) != 3 or not ch[0].isdigit() or not ch[1].isdigit():
                continue                       # ligne de total, ou ligne vide
            total += 1
            if len(tete) < 20:
                tete.append((int(ch[0]), int(ch[1]), ch[2]))
        if not total:
            continue
        fait("chaines", f"chaînes distinctes de type « {libelle} »", str(total),
             c.rel(chemin), methode, nature="compte", genre=genre, note=_SANS_DATE)
        for n, octet, valeur in tete:
            fait("chaines", libelle, valeur, c.rel(chemin), methode,
                 confiance="forte", genre=genre, occurrences=n, volume=volume,
                 octet=octet,
                 note=f"{n} occurrence(s) dans les octets du volume {volume} ; la "
                      f"première vers l'octet {octet} — non datée et non imputable : "
                      "à recouper avec une pièce qui, elle, porte une date")
        if total > len(tete):
            fait("limite", f"extrait « {libelle} » rendu en partie", str(total),
                 c.rel(chemin), "les 20 plus fréquentes sont rendues",
                 note="le fichier les porte toutes ; cherchez-y une valeur précise "
                      "avec --indicateurs plutôt que de tout lire")


# ── 8 · la timeline du système de fichiers ────────────────────────────
# La timeline est la plus grosse pièce de la collecte et la plus riche : une
# ligne par date de chaque fichier du disque. Elle ne sert à rien seule — des
# millions de lignes ne se lisent pas. Elle sert à RÉPONDRE : ce fichier
# téléchargé est-il arrivé sur le disque, et quand ? qu'a-t-on écrit sur cette
# clé USB pendant qu'elle était montée ? C'est pour cela qu'elle est lue en
# DERNIER — les autres faits ont posé les questions.

RE_TL_ISO = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)')
MAX_PAR_SUPPORT = 40          # entrées citées par support amovible
MAX_SENSIBLES = 300


def _date_timeline(brut, fuseau):
    """La date d'une ligne mactime : ISO avec « -y », « Sat Sep 02 2019
    14:20:07 » sans. Le fuseau est celui passé à TZ_MACTIME à la collecte."""
    m = RE_TL_ISO.match(brut)
    iso = m.group(1) if m else lire_date(brut)
    if iso and fuseau:
        iso += "Z" if fuseau.upper() == "UTC" else ""
    return iso


def _questions_timeline():
    """Ce que les autres faits demandent à la timeline.

    Rend ({nom de fichier en minuscules: [faits]}, [(préfixe de montage, fait)]).
    """
    fichiers, montages = {}, []
    for f in FAITS:
        if f["categorie"] == "telechargement" or f["fait"] == "fichier ouvert récemment":
            nom = urllib.parse.unquote(str(f["valeur"])).rstrip("/").rsplit("/", 1)[-1]
            if len(nom) > 3:
                fichiers.setdefault(nom.lower(), []).append(f)
        elif f["fait"] == "système de fichiers amovible monté":
            montages.append((str(f["valeur"]).rstrip("/"), f))
    return fichiers, montages


SENSIBLES = re.compile(r'/(\.ssh/|Downloads?/|T[ée]l[ée]chargements?/|media/|run/media/'
                       r'|tmp/\.|\.bash_history|authorized_keys|/root/)', re.I)


def timeline(c):
    chemin = c.un("_mactime.csv", "TIMELINE")
    if not chemin:
        return
    tz = c.un("_fuseau_timeline.txt", "TIMELINE")
    fuseau = c.texte(tz).strip() if tz else None
    fichiers, montages = _questions_timeline()
    trouves, sous_montage = {}, {}
    total, vus = 0, 0

    for ligne in c.lignes(chemin):
        total += 1
        if total == 1:
            continue
        # Date,Size,Type,Mode,UID,GID,Meta,File Name — le nom garde ses virgules
        ch = ligne.split(",", 7)
        if len(ch) < 8:
            continue
        quand, genre, inode, fichier = ch[0], ch[2], ch[6], ch[7].strip().strip('"')
        base, vise = fichier.rsplit("/", 1)[-1].lower(), False
        if base in fichiers:
            vise = True
            # le même nom peut vivre à deux endroits — dans le dossier de
            # téléchargement ET sur la clé USB : les deux sont des faits
            ou = trouves.setdefault(base, [])
            if len(ou) < 3 and not any(x[3] == fichier for x in ou):
                ou.append((quand, genre, inode, fichier))
        for prefixe, _ in montages:
            if fichier.startswith(prefixe + "/"):
                vise = True
                liste = sous_montage.setdefault(prefixe, [])
                if len(liste) < MAX_PAR_SUPPORT:
                    liste.append((quand, genre, fichier))
        # la pêche large ne redit pas ce qu'une question précise dira mieux
        if not vise and vus < MAX_SENSIBLES and SENSIBLES.search(fichier):
            vus += 1
            fait("timeline", "activité sur un chemin sensible", fichier, c.rel(chemin),
                 "chemins d'intérêt dans la timeline mactime",
                 horodatage=_date_timeline(quand, fuseau), genre=genre, inode=inode or None,
                 note=f"{genre} — {_GENRES.get(genre.replace('.', '') or '', 'dates du fichier')}")

    fait("timeline", "entrées dans la timeline du système de fichiers",
         str(max(0, total - 1)), c.rel(chemin), "mactime -b corps -d -y, puis wc -l",
         note="corps lus sur le périphérique quand un lecteur existait"
              + (f" ; dates écrites dans le fuseau {fuseau}" if fuseau else
                 " ; fuseau de la timeline inconnu — TZ_MACTIME n'a pas été relevé"))

    # ── ce que la timeline confirme, ou pas ──
    for base, demandeurs in sorted(fichiers.items()):
        for f in demandeurs:
            if base in trouves:
                for quand, genre, inode, fichier in trouves[base]:
                    fait("timeline", "fichier retrouvé sur le disque", fichier, c.rel(chemin),
                         f"nom du fichier de {f['id']} cherché dans la timeline",
                         horodatage=_date_timeline(quand, fuseau), acteur=f.get("acteur"),
                         confirme=f["id"], genre=genre, inode=inode or None,
                         note=f"{_GENRES.get(genre.replace('.', '') or '', 'dates du fichier')}"
                              f" — le fichier annoncé par {f['id']} existe bien sur le disque"
                              + (f" ; {len(trouves[base])} emplacements portent ce nom"
                                 if len(trouves[base]) > 1 else ""))
            else:
                fait("timeline", "fichier NON retrouvé sur le disque", base, c.rel(chemin),
                     f"nom du fichier de {f['id']} cherché dans la timeline",
                     acteur=f.get("acteur"), confirme=f["id"], confiance="à vérifier",
                     note="effacé depuis, renommé, ou sur un volume que la timeline ne "
                          "couvre pas — la timeline ne porte que les volumes lus")

    for prefixe, f in montages:
        entrees = sous_montage.get(prefixe, [])
        if not entrees:
            fait("timeline", "aucune trace de fichier sur ce support amovible", prefixe,
                 c.rel(chemin), f"chemins sous « {prefixe}/ » dans la timeline",
                 acteur=f.get("acteur"), confirme=f["id"], confiance="à vérifier",
                 note="le contenu d'un support monté n'est dans la timeline que si le "
                      "support lui-même a été lu : sans lui, on ne sait pas")
            continue
        for quand, genre, fichier in entrees:
            ecrit = "b" in genre or "m" in genre
            fait("timeline",
                 "fichier écrit sur un support amovible" if ecrit
                 else "fichier lu sur un support amovible",
                 fichier, c.rel(chemin), f"chemins sous « {prefixe}/ » dans la timeline",
                 horodatage=_date_timeline(quand, fuseau), acteur=f.get("acteur"),
                 confirme=f["id"], genre=genre,
                 # « écrit » et « lu » ne se commentent pas de la même phrase :
                 # une création sous le point de montage est une copie VERS le
                 # support, une lecture seule n'est pas une copie du tout.
                 note=_GENRES.get(genre.replace(".", "") or "", "dates du fichier")
                      + (" — un fichier créé ou modifié sous le point de montage "
                         "est une COPIE VERS le support" if ecrit else
                         " — une lecture, pas une copie : si le fichier a été "
                         "recopié vers le poste, c'est le même nom, ailleurs "
                         "dans la timeline, qui le dira"))


_GENRES = {
    "m": "contenu modifié", "a": "contenu lu", "c": "droits ou nom changés",
    "b": "fichier créé", "ma": "créé ou modifié, puis lu", "mac": "écrit puis lu",
    "macb": "créé, écrit et lu à cette date", "mb": "créé et écrit",
    "mc": "contenu et métadonnées changés", "mcb": "créé, écrit, métadonnées posées",
    "ab": "créé puis lu", "ac": "lu, métadonnées changées", "acb": "créé, lu",
    "cb": "créé, métadonnées posées",
}


# ── 9 bis · ce que contiennent les fichiers rendus sans nom ───────────
# photorec et xfs_undelete rendent du contenu SANS NOM NI DATE. Les compter
# par type ne dit rien ; les ouvrir dit tout. Cette fonction répond à trois
# questions pour chacun de ceux qu'on sait lire : comment il s'appelle dans la
# collecte, de quoi il parle, et s'il porte quelque chose d'utile.
#
# Elle ne conclut rien. Un document rendu par le carving n'a ni auteur ni date,
# et peut aussi bien venir d'un paquet d'installation que du dossier du compte.
# Elle dit ce qu'il y a dedans et laisse l'analyste ouvrir la pièce.

# Ces motifs-là courent sur le TEXTE décodé, pas sur les octets : un littéral
# d'octets ne peut pas porter d'accent, et « réunion » ou « procédure » sont
# précisément les mots qui disent qu'un document a été rédigé par quelqu'un.
RE_COURRIEL = re.compile(r'[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{2,63}\.[A-Za-z]{2,12}')
RE_MAISON = re.compile(r'/(?:home|root)/[A-Za-z0-9._-]{2,32}/')
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_TELEPHONE = re.compile(r'\b0[1-9](?:[ .-]?\d{2}){4}\b')
RE_REDIGE = re.compile(r'\b(bonjour|madame|monsieur|cordialement|compte[ -]rendu|'
                       r'objet\s*:|réunion|facture|devis|contrat|procédure|'
                       r'note de service)\b', re.I)
RE_SYSTEME = re.compile(r'(/etc/[a-z0-9._/-]{2,}|\bsystemd\b|\b(?:apt|dnf|yum|pacman|'
                        r'zypper)\b|^#!\s*/|\bListen\b|\bServerName\b)', re.I | re.M)

# Le contenu d'un document ne se lit pas en entier : on veut savoir de quoi il
# parle, pas le recopier. Le début suffit, et il borne le coût.
APERCU = 4000
DOCUMENTS_MAX = 40


def _lisible(blob):
    """Le texte d'un blob, s'il en est un. None sinon.

    Un fichier rendu par le carving n'a pas d'extension fiable : on regarde ce
    qu'il contient. Un octet nul, ou plus d'un dixième d'octets non
    imprimables, et ce n'est pas du texte — c'est une image ou un binaire, et
    l'aperçu n'aurait aucun sens.
    """
    if not blob or b"\x00" in blob[:4096]:
        return None
    echantillon = blob[:4096]
    imprimables = sum(1 for o in echantillon if 32 <= o < 127 or o in (9, 10, 13) or o >= 160)
    if imprimables < len(echantillon) * 0.9:
        return None
    # Une plage d'un seul octet répété passe tous les tests d'imprimabilité et
    # n'est pourtant pas du texte : c'est du remplissage, ou la fin d'un bloc.
    # Un disque en produit beaucoup, et un rapport qui les présente comme des
    # documents lisibles fait perdre du temps à celui qui le lit.
    if len(set(echantillon)) < 12:
        return None
    return blob.decode("utf-8", "replace")


def _sujet(texte):
    """De quoi ça parle, en une ligne : la première qui dise quelque chose."""
    for ligne in texte.splitlines():
        nue = re.sub(r'<[^>]{1,200}>', " ", ligne)       # balises XML d'un .docx
        nue = " ".join(nue.split())
        if len(nue) >= 12 and not nue.startswith(("#!", "<?xml", "%PDF")):
            return nue[:160]
    return None


def documents(c):
    """Les fichiers rendus sans nom, ouverts et caractérisés."""
    rendus, tronque = 0, False
    for dossier in ("PHOTOREC", "SUPPRIMES"):
        base = os.path.join(c.racine, dossier)
        if not os.path.isdir(base):
            continue
        for d, sous, fichiers in sorted(os.walk(base)):
            sous.sort()
            for f in sorted(fichiers):
                if rendus >= DOCUMENTS_MAX:
                    tronque = True
                    continue
                chemin = os.path.join(d, f)
                etat = {}
                morceaux, vus = [], 0
                try:
                    for _, clair in _blocs(chemin, etat):
                        if not clair:
                            continue
                        morceaux.append(clair)
                        vus += len(clair)
                        if vus >= APERCU:
                            break
                except (OSError, zlib.error):
                    continue
                texte = _lisible(b"".join(morceaux)[:APERCU])
                if not texte:
                    continue
                sujet = _sujet(texte)
                porte = []
                if RE_COURRIEL.search(texte) or RE_MAISON.search(texte) \
                        or RE_TELEPHONE.search(texte) or RE_REDIGE.search(texte):
                    porte.append("utilisateur")
                if RE_SYSTEME.search(texte) or RE_IPV4.search(texte):
                    porte.append("système")
                octets = texte.encode("utf-8", "replace")
                interessants = [nom for nom, motif, _ in INTERETS
                                if re.search(motif.encode("utf-8"), octets, re.I)]
                if interessants:
                    porte.append("forensic")
                rendus += 1
                fait("document", "fichier rendu sans nom, et lisible",
                     sujet or "(du texte, sans phrase identifiable)", c.rel(chemin),
                     f"ouvert et lu sur ses {_taille(min(vus, APERCU))} premiers octets",
                     confiance="forte", porte=" / ".join(porte) or "rien de remarquable",
                     interet=" / ".join(interessants) or None,
                     note="rendu par le carving : ni nom d'origine, ni date, ni compte. "
                          "Ce qu'il contient est établi ; d'où il vient ne l'est pas"
                          + (f". Motifs repérés dedans : {', '.join(interessants)}"
                             if interessants else ""))
    if tronque:
        fait("limite", "documents rendus sans nom : seuls les premiers sont ouverts",
             str(DOCUMENTS_MAX), "PHOTOREC/, SUPPRIMES/",
             f"les {DOCUMENTS_MAX} premiers dans l'ordre des dossiers",
             note="les autres sont comptés par type dans la section des pièces "
                  "récupérées ; pour en ouvrir un précis, cherchez-y avec "
                  "--indicateurs")


# ── 10 · les synthèses ────────────────────────────────────────────────
# Ces deux-là ne lisent aucune pièce : elles relisent les FAITS déjà établis.
# C'est voulu. Un tableau de synthèse qui irait rechercher ses propres données
# pourrait dire autre chose que le corps du rapport ; celui-ci ne le peut pas,
# et chaque ligne cite les identifiants des faits dont elle sort. Le lecteur
# peut donc remonter de la synthèse à la pièce, ce qui est tout l'intérêt.

def _horo(f):
    """L'horodatage d'un fait, en datetime comparable, ou None.

    Les faits portent trois formes : epoch converti en UTC (suffixe Z), heure
    du poste avec décalage, et heure locale sans fuseau quand la pièce n'en
    donne pas. On compare des instants : les deux premières sont ramenées à
    UTC, la troisième est prise telle quelle, ce qui suffit pour situer un jour
    et mesurer un écart de plusieurs semaines.
    """
    h = f.get("horodatage")
    if not h:
        return None
    try:
        d = datetime.fromisoformat(h.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.astimezone(timezone.utc).replace(tzinfo=None) if d.tzinfo else d


# Un trou plus court que ça n'est pas un fait : un poste ne sert pas tous les
# jours, un week-end en fait déjà deux. Quatorze jours, c'est plus qu'un congé
# ordinaire, et c'est la durée à partir de laquelle l'absence mérite d'être
# posée comme une question.
TROU_JOURS = 14


def periodes(c):
    """Quand le poste a laissé des traces, et quand il n'en a laissé aucune.

    L'absence de trace n'est PAS l'absence d'usage, et c'est le seul point qui
    compte ici : wtmp est tourné, les journaux sont purgés, un compte peut
    travailler sans rien écrire que la collecte ait pris. Chaque période sans
    trace est donc posée comme une question — « rien entre le X et le Y » —,
    jamais comme un constat d'inutilisation. Le fait le dit en toutes lettres,
    pour qu'aucune reprise dans le rapport ne puisse le durcir.
    """
    # Départager les ex æquo sur l'identifiant : deux faits au même instant
    # sont fréquents (une ligne de journal en produit plusieurs), et sans ce
    # second critère la borne citée changerait d'une exécution à l'autre.
    dates = sorted(((h, f) for f in FAITS for h in (_horo(f),) if h),
                   key=lambda x: (x[0], x[1]["id"]))
    if len(dates) < 2:
        return
    debut, fin = dates[0], dates[-1]
    fait("periode", "première trace datée de la collecte",
         debut[0].date().isoformat(), debut[1]["source"],
         f"le plus ancien horodatage des {len(dates)} faits datés",
         horodatage=debut[1].get("horodatage"), depuis=debut[1]["id"],
         note=f"fait {debut[1]['id']} : {debut[1]['fait']}")
    fait("periode", "dernière trace datée de la collecte",
         fin[0].date().isoformat(), fin[1]["source"],
         f"le plus récent horodatage des {len(dates)} faits datés",
         horodatage=fin[1].get("horodatage"), depuis=fin[1]["id"],
         note=f"fait {fin[1]['id']} : {fin[1]['fait']} — au-delà, la collecte ne "
              "dit rien, ce qui ne veut pas dire que le poste s'est arrêté")
    for (h1, f1), (h2, f2) in zip(dates, dates[1:]):
        ecart = (h2 - h1).days
        if ecart < TROU_JOURS:
            continue
        # La source est la collecte ENTIÈRE, pas une pièce : un trou n'existe
        # que parce qu'AUCUNE pièce ne porte de date sur la période. Nommer ici
        # les deux pièces qui le bornent laisserait croire que le trou vient
        # d'elles ; elles sont dans la note, avec les identifiants.
        fait("periode", "aucune trace pendant une longue période",
             f"du {h1.date().isoformat()} au {h2.date().isoformat()}", c.prefix,
             "écart entre deux faits datés consécutifs, toutes pièces confondues",
             horodatage=f1.get("horodatage"), jours=ecart, confiance="à vérifier",
             depuis=f1["id"], jusqu=f2["id"],
             note=f"borné par {f1['id']} ({f1['fait']}, {f1['source']}) et "
                  f"{f2['id']} ({f2['fait']}, {f2['source']}). "
                  "CE N'EST PAS UNE PREUVE DE NON-USAGE : wtmp est tourné, les "
                  "journaux sont purgés, et un usage qui n'écrit rien ne laisse "
                  "rien. À confronter aux limites de collecte du rapport")


RE_VIDPID = re.compile(r'idVendor=(?P<vid>[0-9a-fA-F]{4}).*?idProduct=(?P<pid>[0-9a-fA-F]{4})')


def supports(c):
    """Un support amovible par ligne, au lieu d'événements épars.

    Le journal écrit le branchement, le numéro de série et le montage sur des
    lignes séparées, à quelques secondes d'écart. Les recoller donne ce qu'un
    lecteur cherche vraiment : quel support, reconnu à quoi, vu quand pour la
    première et la dernière fois, monté où et par qui.

    Le rapprochement se fait sur le TEMPS, parce que c'est ce que le journal
    donne — le numéro de série suit son branchement de moins d'une minute. Un
    numéro rattaché de cette façon est donc « forte », pas « certaine », et le
    fait porte les identifiants des deux lignes pour qu'on puisse vérifier.
    """
    branchements = [f for f in FAITS if f["fait"] == "support amovible USB branché"]
    series = [f for f in FAITS if f["fait"] == "numéro de série du support USB"]
    montages = [f for f in FAITS if f["fait"] == "système de fichiers amovible monté"]
    if not branchements:
        return
    appareils = {}
    for f in branchements:
        m = RE_VIDPID.search(f["valeur"] or "")
        cle = (m.group("vid").lower(), m.group("pid").lower()) if m else ("?", "?")
        a = appareils.setdefault(cle, {"vues": [], "series": {}, "montages": {}})
        a["vues"].append(f)
        h = _horo(f)
        # même seconde ou presque : le journal écrit les deux lignes d'affilée
        for g in series:
            hg = _horo(g)
            if h and hg and abs((hg - h).total_seconds()) <= 60:
                a["series"].setdefault(g["valeur"], g["id"])
        for g in montages:
            hg = _horo(g)
            if h and hg and 0 <= (hg - h).total_seconds() <= 300:
                a["montages"].setdefault(g["valeur"], (g["id"], g.get("acteur")))
    for (vid, pid), a in sorted(appareils.items()):
        vues = sorted(a["vues"], key=lambda f: _horo(f) or datetime.min)
        ids = ", ".join(f["id"] for f in vues[:8])
        comptes = sorted({c_ for _, c_ in a["montages"].values() if c_})
        fait("appareil", "support amovible reconnu",
             " / ".join(a["series"]) or f"{vid}:{pid} (sans numéro de série lu)",
             vues[0]["source"], "branchements du journal regroupés par idVendor:idProduct",
             horodatage=vues[0].get("horodatage"),
             confiance="forte" if a["series"] else "à vérifier",
             vid=vid, pid=pid, branchements=len(vues),
             premiere=vues[0].get("horodatage"), derniere=vues[-1].get("horodatage"),
             montages=" / ".join(a["montages"]) or None,
             acteur=comptes[0] if len(comptes) == 1 else None,
             note=f"idVendor={vid} idProduct={pid} ; {len(vues)} branchement(s) "
                  f"({ids})"
                  + (f" ; monté par {', '.join(comptes)}" if comptes else
                     " ; aucun montage relevé — branché sans être monté, ou montage "
                     "hors des journaux collectés")
                  + ("" if a["series"] else " ; AUCUN numéro de série dans le journal : "
                     "deux supports du même modèle ne se distinguent pas"))


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
                        "quand": _epoch_iso(sec)})
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
                        "quand": _epoch_iso(sec)})
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
    ("STRINGS", "_strings_", "les chaînes lisibles des périphériques",
     "le périphérique de chaque volume monté sous MONTAGE",
     "Chaînes lisibles de {{volume}}",
     ("la collecte a été faite avant que l'étape n'existe, ou passée faute de "
      "place — un strings de disque pèse des dizaines de gigaoctets", ())),
    ("PAQUETS", "_paquets.txt", "la liste des paquets",
     "/var/lib/rpm, /var/lib/dpkg, /var/lib/pacman/local ou /lib/apk/db/installed",
     "Paquets installés",
     ("l'image n'a aucune base de paquets connue ; vide : sur openSUSE, la base RPM "
      "est au format ndb que le rpm du poste d'analyse ne lit pas toujours — les "
      "poses sont dans var/log/zypp/history", ())),
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
     ("Fedora 40+ et Debian 13+ n'ont plus wtmp, mais wtmp.db ; Alpine (musl) n'a pas "
      "d'utmp du tout", ("alpine",))),
    ("CONNEXIONS", ("btmp", "_echecs.txt"), "les échecs d'authentification",
     "/var/log/btmp et ses rotations", "Copie des fichiers de connexion",
     ("btmp est souvent absent ou désactivé", ("alpine",))),
    ("JOURNAUX", "_journal.txt", "le journal systemd en clair",
     "/var/log/journal/<machine-id>/*.journal", "Journal systemd, en clair",
     ("l'image n'a pas de journal persistant sur disque ; sans systemd (Alpine, "
      "Devuan), tout est dans /var/log/messages", ("alpine", "devuan"))),
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
        # le binaire wtmp OU la sortie texte de « last » suffisent. Une pièce
        # présente mais vide n'a pas été collectée non plus.
        motifs = motif if isinstance(motif, tuple) else (motif,)
        presentes = [f for m in motifs for f in c.chercher(m, dossier)]
        if any(os.path.getsize(f) for f in presentes):
            continue
        raison, familles = normal if isinstance(normal, tuple) else (normal, ())
        connue = bool(familles) and bool(set(familles) & c.familles)
        note = (f"à reprendre sur l'image montée : {origine}. "
                f"Étape de collecte-linux.conf : « {etape} » — "
                f"la rejouer seule avec --only <numéro du plan>.")
        if raison:
            note += f" Absence normale si {raison}."
        if connue:
            note += (f" Le système est de famille {', '.join(sorted(c.familles))} : "
                     "cette absence est attendue.")
        fait("limite",
             f"pièce {'vide' if presentes else 'absente'} de la collecte : {quoi}"
             + (" — normal sur cette famille" if connue else ""),
             " ou ".join(f"{dossier}/…{m}" for m in motifs), dossier + "/",
             "recherche du motif dans la collecte, et de sa taille",
             confiance="certaine" if connue else "à vérifier", note=note)


# ── 10 · ce qu'on vient chercher : chaînes, empreintes, adresses ─────
# L'analyste sait parfois ce qu'il cherche — l'empreinte d'un fichier vu
# ailleurs, une adresse, un nom. Le fichier d'indicateurs se lit à la main :
# une ligne par indicateur, « type: valeur », un # pour l'étiquette.
#
#   sha256: / sha1: / md5:   une empreinte, comparée à CHAQUE fichier de la
#                            collecte — membres des archives et fichiers posés,
#                            photorec compris
#   texte:                   une chaîne, cherchée telle quelle, sans la casse
#   regex:                   une expression, cherchée dans les octets
#   ip: / domaine:           une adresse ou un nom, cherchés comme un texte
#   fichier:                 un nom ou un motif de nom (« *.torrent », « id_rsa »)
TYPES_INDICATEUR = ("sha256", "sha1", "md5", "texte", "regex", "ip", "domaine", "fichier")


# ── ce que l'outil cherche de lui-même ────────────────────────────────
# Ces motifs ne viennent pas de l'analyste : ils sont cherchés à chaque
# extraction, dans TOUTE la collecte — donc aussi dans les chaînes du disque
# et dans ce que photorec a rendu, où le reste du rapport ne va pas.
#
# La liste est COURTE, et c'est délibéré. Sur des dizaines de gigaoctets
# d'octets bruts, un motif approximatif ne rend pas un indice : il rend des
# milliers de faux, et un rapport que personne ne relit. N'y figure donc que
# ce qui a une forme reconnaissable et peu d'homonymes. Ont été écartés pour
# cette raison : les adresses bitcoin et ethereum (du base58 et de
# l'hexadécimal, qu'un disque produit par accident à la pelle), les IBAN
# génériques, et les numéros de carte — qui demandent une vérification de Luhn
# qu'une expression rationnelle ne sait pas faire.
#
# Chaque fait qui en sort est « à vérifier » et jamais autre chose : trouvé
# dans l'espace libre, un secret n'est ni daté, ni imputable, et peut venir
# d'un paquet d'installation autant que d'un fichier de l'utilisateur.
INTERETS = [
    ("clé privée", r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY',
     "une clé privée en clair ; comparez-la aux clés des comptes"),
    ("mot de passe en clair", r'(?:password|passwd|mot_?de_?passe)["\s]{0,3}[=:]["\s]{0,3}[^\s"\',;]{6,64}',
     "un mot de passe écrit en clair dans un fichier ou dans l'espace libre"),
    ("identifiants dans une URL", r'\b[a-z][a-z0-9+.-]{1,10}://[^\s:/@]{1,64}:[^\s@/]{3,64}@[^\s/]{3,}',
     "un identifiant et un secret passés dans une adresse"),
    ("chaîne de connexion", r'\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ldaps?)://[^\s]{4,}',
     "une base de données ou un annuaire joint depuis ce poste"),
    ("jeton AWS", r'\bAKIA[0-9A-Z]{16}\b', "une clé d'accès Amazon"),
    ("jeton GitHub", r'\bgh[pousr]_[A-Za-z0-9]{36}\b', "un jeton GitHub"),
    ("jeton Slack", r'\bxox[baprs]-[A-Za-z0-9-]{10,}', "un jeton Slack"),
    ("clé Google", r'\bAIza[0-9A-Za-z_-]{35}\b', "une clé d'API Google"),
    ("adresse en .onion", r'\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b',
     "un service accessible seulement par Tor"),
    ("clé de réseau sans fil", r'\bpsk["\s]{0,3}=["\s]{0,3}[^\s"\',;]{8,63}',
     "la clé d'un réseau sans fil, en clair"),
    ("couple identifiant/mot de passe",
     r'\b[\w.+-]{3,64}@[\w.-]{3,}\.[a-z]{2,12}:[^\s:]{4,64}\b',
     "la forme des listes de comptes qui circulent après une fuite"),
]


def interets():
    """Les motifs de l'outil, à la forme que le moteur d'indicateurs attend.

    Même liste, même moteur, même chercheur que --indicateurs : il n'y a qu'une
    façon de parcourir la collecte, et elle sert aux deux. « absent » à False
    parce qu'un motif de cette liste qu'on ne trouve pas n'est pas un fait —
    ne pas avoir de clé privée qui traîne est la normale, pas une découverte.
    """
    return [{"genre": nom, "valeur": nom, "motif": re.compile(m.encode("utf-8"), re.I),
             "etiquette": quoi, "categorie": "interet", "absent": False}
            for nom, m, quoi in INTERETS]


def lire_indicateurs(chemin):
    liste = []
    with open(chemin, encoding="utf-8") as fh:
        for num, ligne in enumerate(fh, 1):
            nue = ligne.strip()
            if not nue or nue.startswith("#"):
                continue
            etiquette = None
            coupe = re.search(r'\s+#\s*(.*)$', nue)
            if coupe:
                etiquette, nue = coupe.group(1).strip() or None, nue[:coupe.start()].strip()
            if ":" not in nue:
                sys.exit(f"{chemin}:{num} : attendu « type: valeur » — {nue}")
            genre, valeur = (x.strip() for x in nue.split(":", 1))
            genre = genre.lower()
            if genre not in TYPES_INDICATEUR:
                sys.exit(f"{chemin}:{num} : type « {genre} » inconnu — attendu "
                         + ", ".join(TYPES_INDICATEUR))
            if genre in ("sha256", "sha1", "md5"):
                valeur = valeur.lower()
                if not re.fullmatch(r'[0-9a-f]{%d}' % {"sha256": 64, "sha1": 40, "md5": 32}[genre], valeur):
                    sys.exit(f"{chemin}:{num} : {genre} mal formée — {valeur}")
                motif = None
            elif genre == "regex":
                try:
                    motif = re.compile(valeur.encode("utf-8"), re.I)
                except re.error as e:
                    sys.exit(f"{chemin}:{num} : expression illisible ({e}) — {valeur}")
            elif genre == "fichier":
                motif = None
            else:
                motif = re.compile(re.escape(valeur.encode("utf-8")), re.I)
            liste.append({"genre": genre, "valeur": valeur, "motif": motif,
                          "etiquette": etiquette})
    if not liste:
        sys.exit(f"{chemin} : aucun indicateur lisible")
    return liste


# Ce que photorec rend d'un traitement de texte est un .docx : un zip de XML.
# Les motifs n'y verraient rien sans le décompresser, alors que le texte est
# bien là — et c'est souvent le contenu le plus parlant de tout PHOTOREC.
#
# La borne n'est pas une précaution de style : une archive peut se décompresser
# en téraoctets (« zip bomb »), et une collecte forensique est justement
# l'endroit où l'on trouve des fichiers hostiles. Au-delà, on s'arrête et on le
# DIT — un fait « limite », jamais un silence.
PLAFOND_ARCHIVE = 256 << 20
_ZIP = (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".jar", ".apk")
RE_FLUX_PDF = re.compile(rb'stream\r?\n(.*?)endstream', re.S)


def _membres_zip(chemin, etat):
    import zipfile
    rendu = 0
    try:
        with zipfile.ZipFile(chemin) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if rendu + info.file_size > PLAFOND_ARCHIVE:
                    etat["tronque"] = "plafond d'archive atteint"
                    return
                try:
                    with z.open(info) as fh:
                        yield fh.read()
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    continue           # membre chiffré ou abîmé : les autres restent
                rendu += info.file_size
    except (OSError, zipfile.BadZipFile, EOFError, ValueError):
        etat["illisible"] = "archive illisible"


def _flux_pdf(chemin, etat):
    """Les flux compressés d'un PDF, quand ils le sont en zlib.

    Un PDF n'est pas une archive : c'est un format à objets, dont le texte vit
    dans des flux souvent comprimés en FlateDecode. On ne cherche pas à le
    rendre lisible — extraire un texte de PDF demande une bibliothèque —, on
    veut seulement que les octets DÉCOMPRESSÉS passent sous les motifs. Un
    mot de passe écrit dans un PDF y devient visible ; sa mise en page, non.
    """
    try:
        with open(chemin, "rb") as fh:
            brut = fh.read(PLAFOND_ARCHIVE)
    except OSError:
        return
    rendu = 0
    for m in RE_FLUX_PDF.finditer(brut):
        try:
            clair = zlib.decompress(m.group(1))
        except zlib.error:
            continue                   # flux non comprimé, ou autre filtre
        rendu += len(clair)
        if rendu > PLAFOND_ARCHIVE:
            etat["tronque"] = "plafond d'archive atteint"
            return
        yield clair


def _decomprime(chemin, etat):
    """Le contenu lisible d'un fichier comprimé, morceau par morceau, ou None.

    None veut dire « ce fichier est déjà son propre contenu » — et c'est ce qui
    permet à _blocs de n'avoir qu'une forme de sortie pour tout le monde.
    """
    bas = chemin.lower()
    if bas.endswith(_ZIP):
        return _membres_zip(chemin, etat)
    if bas.endswith(".pdf"):
        return _flux_pdf(chemin, etat)
    for suffixe, ouvrir in ((".bz2", bz2.open), (".xz", lzma.open), (".lzma", lzma.open)):
        if bas.endswith(suffixe):
            def flux(ouvrir=ouvrir):
                try:
                    with ouvrir(chemin, "rb") as fh:
                        rendu = 0
                        for m in iter(lambda: fh.read(1 << 20), b""):
                            rendu += len(m)
                            if rendu > PLAFOND_ARCHIVE:
                                etat["tronque"] = "plafond d'archive atteint"
                                return
                            yield m
                except (OSError, EOFError, ValueError):
                    etat["illisible"] = "archive illisible"
            return flux()
    return None


def _blocs(chemin, etat=None, bloc=1 << 20):
    """Rend (brut, clair) : les octets du fichier, et son contenu lisible.

    Le strings d'un disque pèse des gigaoctets : il ne peut être ni chargé en
    mémoire, ni lu deux fois. Tout passe donc en flux. L'empreinte se calcule
    sur « brut », les motifs courent sur « clair » — pour un fichier ordinaire
    les deux sont le même bloc, et rien n'est copié.

    Un .gz se décompresse au fil des blocs bruts, ce qui donne les deux en UNE
    lecture. Une archive (zip, docx, pdf, bz2, xz) se lit deux fois : ses
    octets pour l'empreinte, puis son contenu. C'est le prix pour voir dans un
    document rendu par photorec, et il ne se paie que sur ces fichiers-là.
    """
    etat = {} if etat is None else etat
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS) if chemin.endswith(".gz") else None
    contenu = None if dec else _decomprime(chemin, etat)
    with open(chemin, "rb") as fh:
        for brut in iter(lambda: fh.read(bloc), b""):
            yield brut, (dec.decompress(brut) if dec else
                         (b"" if contenu is not None else brut))
    if contenu is not None:
        for morceau in contenu:
            yield b"", morceau


class Reprise:
    """Un journal de progression, pour ne pas tout refaire après un plantage.

    Le parcours des indicateurs est la partie longue : il lit chaque octet de
    la collecte, décompresse des gigaoctets de chaînes, ouvre chaque archive.
    Sur un gros dossier c'est des heures — et un plantage à la fin les perdait
    toutes.

    Le journal note, fichier par fichier, ce qu'il a produit. À la reprise, un
    fichier dont la TAILLE et la DATE n'ont pas bougé n'est pas relu : ses
    faits sont rejoués tels quels. Les scellés étant montés en lecture seule,
    ces deux critères suffisent — et s'ils bougent, c'est que la collecte a
    changé, auquel cas il FAUT relire.

    Le journal porte aussi l'empreinte de la liste d'indicateurs : la changer
    invalide tout, puisque les faits d'avant répondaient à d'autres questions.

    Écrit et vidé après CHAQUE fichier : un plantage ne coûte que le fichier en
    cours. C'est ce qui distingue un journal de reprise d'un cache.
    """

    def __init__(self, chemin, signature):
        self.chemin, self.signature, self.connus = chemin, signature, {}
        self.fh = None

    def charger(self):
        """Ce qui est réutilisable du journal précédent, s'il en reste."""
        try:
            with open(self.chemin, encoding="utf-8") as fh:
                entetes = fh.readline()
                if json.loads(entetes).get("signature") != self.signature:
                    return 0          # d'autres indicateurs : rien n'est réutilisable
                for ligne in fh:
                    try:
                        e = json.loads(ligne)
                    except json.JSONDecodeError:
                        break         # dernière ligne coupée par le plantage
                    self.connus[e["chemin"]] = e
        except (OSError, json.JSONDecodeError, KeyError):
            self.connus = {}
        return len(self.connus)

    def ouvrir(self):
        self.fh = open(self.chemin, "w", encoding="utf-8")
        self.fh.write(json.dumps({"signature": self.signature},
                                 ensure_ascii=False) + "\n")
        self.fh.flush()
        return self

    def reutilisable(self, rel, chemin):
        e = self.connus.get(rel)
        if not e:
            return None
        try:
            st = os.stat(chemin)
        except OSError:
            return None
        return e if (e.get("taille") == st.st_size
                     and e.get("mtime") == int(st.st_mtime)) else None

    def noter(self, rel, chemin, faits, trouves):
        if not self.fh:
            return
        try:
            st = os.stat(chemin)
        except OSError:
            return
        self.fh.write(json.dumps(
            {"chemin": rel, "taille": st.st_size, "mtime": int(st.st_mtime),
             "faits": [{k: v for k, v in f.items() if k != "id"} for f in faits],
             "trouves": sorted(trouves)}, ensure_ascii=False) + "\n")
        self.fh.flush()          # après CHAQUE fichier, sinon ce n'est pas une reprise

    def fermer(self):
        if self.fh:
            self.fh.close()
            self.fh = None


def _rejouer(f):
    """Repose un fait du journal, avec un identifiant neuf.

    Les identifiants sont séquentiels : rejoués dans le même ordre, ils
    retombent sur les mêmes. C'est ce qui permet à un rapport repris de citer
    les mêmes numéros qu'un rapport d'un seul tenant.
    """
    FAITS.append({"id": f"F{len(FAITS) + 1:04d}", **f})


def indicateurs(c, liste, fichier=None, reprise=None):
    """Cherche chaque indicateur dans TOUTE la collecte, fichier par fichier.

    Une seule alternative pour tous les motifs : un membre de 200 Mo n'est
    balayé qu'une fois. Les empreintes se calculent en flux. Et quand seuls des
    noms sont demandés, rien n'est lu.
    """
    empreintes = {g: {x["valeur"]: x for x in liste if x["genre"] == g}
                  for g in ("sha256", "sha1", "md5")}
    empreintes = {g: d for g, d in empreintes.items() if d}
    noms = [x for x in liste if x["genre"] == "fichier"]
    motifs = [x for x in liste if x["motif"] is not None]
    alternative = re.compile(b"|".join(b"(?P<i%d>%s)" % (i, x["motif"].pattern)
                                       for i, x in enumerate(motifs))) if motifs else None
    lire = bool(empreintes or motifs)

    def examiner(source, nom, blocs=None, chevauche=1 << 12):
        """Le nom, l'empreinte et les motifs, en UNE lecture.

        « blocs » est une suite de (brut, clair) — un seul couple pour un
        membre d'archive déjà en mémoire, autant que nécessaire pour un gros
        fichier. Tout passe par ici : sans quoi une source qu'on ne peut pas
        charger d'un bloc réclame un second chercheur, et les deux divergent
        — la première victime étant le contrôle des NOMS, qui n'a rien à voir
        avec la taille du fichier.

        Le chevauchement n'est pas un détail : une chaîne à cheval sur deux
        blocs serait invisible sans lui. On garde donc la queue du bloc
        précédent, et on ignore ce qui tombe entièrement dedans, sinon la même
        occurrence serait comptée deux fois.
        """
        base = os.path.basename(nom)
        for x in noms:
            if fnmatch.fnmatch(base, x["valeur"]) or fnmatch.fnmatch(nom, x["valeur"]):
                x["trouve"] = True
                fait(x.get("categorie", "indicateur"), "fichier au nom recherché",
                     nom, source, f"nom comparé au motif « {x['valeur']} »",
                     note=x["etiquette"])
        if blocs is None:
            return
        hs = {g: hashlib.new(g) for g in empreintes}
        comptes_, contextes = {}, {}
        reste, depart = b"", 0
        for brut, clair in blocs:
            for h in hs.values():
                h.update(brut)
            if not alternative:
                continue
            tampon = reste + clair
            for m in alternative.finditer(tampon):
                if m.end() <= len(reste):
                    continue                       # déjà compté au tour d'avant
                i = int(m.lastgroup[1:])
                comptes_[i] = comptes_.get(i, 0) + 1
                if i not in contextes:
                    d, f = max(0, m.start() - 60), min(len(tampon), m.end() + 60)
                    contextes[i] = (tampon[d:f].decode("utf-8", "replace")
                                    .replace("\n", " "), depart + m.start())
            reste = tampon[-chevauche:]
            depart += len(tampon) - len(reste)
        for g, attendus in empreintes.items():
            h = hs[g].hexdigest()
            if h in attendus:
                attendus[h]["trouve"] = True
                fait(attendus[h].get("categorie", "indicateur"),
                     f"fichier à l'empreinte {g} recherchée", nom, source,
                     f"{g} du fichier = {h}", note=attendus[h]["etiquette"])
        for i, n in sorted(comptes_.items()):
            x = motifs[i]
            x["trouve"] = True
            contexte, octet = contextes[i]
            interet = x.get("categorie") == "interet"
            fait(x.get("categorie", "indicateur"),
                 # Le genre est dans la VALEUR ; le répéter dans le libellé le
                 # rendrait redondant et bancal — « clé privée repéré ».
                 "repéré dans les octets d'un fichier" if interet
                 else f"{x['genre']} recherché présent dans un fichier",
                 x["valeur"], source,
                 f"motif « {x['valeur']} » cherché dans les octets du fichier",
                 octet=octet, occurrences=n, contexte=contexte,
                 confiance="à vérifier" if interet else "certaine",
                 note=f"{n} occurrence(s) ; la première vers l'octet {octet}, autour "
                      f"d'elle : « {contexte} »"
                      + (f" — {x['etiquette']}" if x["etiquette"] else "")
                      + (". Trouvé dans les octets : ni daté, ni imputable, et peut "
                         "venir d'un paquet d'installation autant que d'un fichier du "
                         "compte. À confirmer sur la pièce citée" if interet else ""))

    # le fichier d'indicateurs posé DANS la collecte se trouverait lui-même :
    # chaque chaîne y figure, par construction
    par_valeur = {x["valeur"]: x for x in liste}
    soi = os.path.abspath(fichier) if fichier else None
    # os.walk n'a pas d'ordre garanti : sans tri, la reprise rejouerait les
    # faits dans un autre ordre que la première fois, et les identifiants
    # changeraient. Le tri est donc ici une exigence, pas un confort.
    for d, sous, fichiers in sorted(os.walk(c.racine)):
        sous.sort()
        for f in sorted(fichiers):
            chemin = os.path.join(d, f)
            if os.path.abspath(chemin) == soi:
                continue
            rel = c.rel(chemin)
            deja = reprise.reutilisable(rel, chemin) if reprise else None
            if deja is not None:
                for x in deja.get("trouves", ()):
                    if x in par_valeur:
                        par_valeur[x]["trouve"] = True
                for fa in deja["faits"]:
                    _rejouer(fa)
                continue
            depart, trouves_avant = len(FAITS), {x["valeur"] for x in liste
                                                 if x.get("trouve")}
            if chemin.endswith(".tar.gz"):
                for nom, blob in c.membres_tar(chemin, None if lire else lambda n: False):
                    examiner(f"{c.rel(chemin)} → {nom}", nom,
                             [(blob, blob)] if blob is not None else None)
                if not lire:
                    for nom in c.mtimes.get(chemin, {}):
                        examiner(f"{c.rel(chemin)} → {nom}", nom)
                if reprise:
                    reprise.noter(rel, chemin, FAITS[depart:],
                                  {x["valeur"] for x in liste if x.get("trouve")}
                                  - trouves_avant)
                continue
            if not lire:
                examiner(c.rel(chemin), c.rel(chemin))
                if reprise:
                    reprise.noter(rel, chemin, FAITS[depart:],
                                  {x["valeur"] for x in liste if x.get("trouve")}
                                  - trouves_avant)
                continue
            c.lus.add(chemin)
            # Une seule voie : _blocs décide seul s'il faut décompresser, et
            # rend toujours des blocs. Un .gz — le strings d'un disque — n'est
            # donc ni chargé d'un coup, ni cherché dans ses octets compressés,
            # où rien ne pourrait correspondre ; et un .txt de plusieurs
            # centaines de mégaoctets ne l'est pas davantage.
            etat = {}
            try:
                examiner(c.rel(chemin), c.rel(chemin), _blocs(chemin, etat))
            except (OSError, zlib.error):
                pass
            # Une archive tronquée ou illisible se DIT : sans ça, un document
            # qu'on n'a pas su ouvrir ressemblerait à un document sans rien
            # dedans, ce qui n'est pas la même chose du tout.
            for cle, quoi in (("tronque", "archive lue en partie"),
                              ("illisible", "archive non lisible")):
                if cle in etat:
                    fait("limite", quoi, c.rel(chemin), c.rel(chemin),
                         "décompression pour y chercher les motifs",
                         note=etat[cle] + f" ; plafond {_taille(PLAFOND_ARCHIVE)}. "
                              "Le contenu non lu n'a été soumis à aucun motif")
            if reprise:
                reprise.noter(rel, chemin, FAITS[depart:],
                              {x["valeur"] for x in liste if x.get("trouve")}
                              - trouves_avant)
    for x in liste:
        if x.get("absent") is False:
            continue          # l'absence d'un motif de l'outil n'est pas un fait
        if not x.get("trouve"):
            fait("indicateur", f"{x['genre']} recherché ABSENT de la collecte", x["valeur"],
                 c.prefix, "recherche dans chaque fichier et chaque membre d'archive",
                 note="absent des pièces collectées, pas forcément du poste : la "
                      "collecte ne prend pas tout"
                      + (f" — {x['etiquette']}" if x["etiquette"] else ""))


def _csv_sain(v):
    """Une cellule qu'un tableur affichera, sans jamais l'exécuter : un nom
    de fichier « =HYPERLINK(...) » deviendrait une formule dans Excel."""
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
    par_cat = collections.Counter(f["categorie"] for f in FAITS)
    return {
        "collecte": c.prefix,
        "chemin_analyse": c.racine,
        "extracteur": {"fichier": os.path.basename(moi),
                       "sha256": empreinte(moi)},
        "commande": " ".join(argv),
        "extrait_le": datetime.now().astimezone().isoformat(),
        "faits": {"total": len(FAITS), "par_categorie": dict(sorted(par_cat.items()))},
        "faits_sha256": empreinte(sortie),
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
    ap.add_argument("--indicateurs", metavar="FICHIER",
                    help="chaînes, empreintes, adresses à chercher dans toute la "
                         "collecte, une par ligne : voir references/indicateurs.md")
    ap.add_argument("--sans-reprise", action="store_true",
                    help="ignorer le journal de reprise et reparcourir toute la "
                         "collecte, même ce qui a déjà été lu")
    args = ap.parse_args()

    c = Collecte(args.collecte, visites=args.visites)
    for etape, fn in (("complétude", completude),
                      ("machine", machine), ("comptes et domaine", comptes),
                      ("sessions", sessions), ("journaux", journaux),
                      ("réseau", reseau), ("navigation", navigation),
                      ("historique des paquets", historique_paquets),
                      ("persistance", persistance), ("supprimés", supprimes),
                      ("chaînes des disques", chaines),
                      ("documents rendus", documents), ("timeline", timeline),
                      ("périodes", periodes), ("supports amovibles", supports)):
        avant = len(FAITS)
        try:
            fn(c)
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! {etape} : {type(e).__name__} {e}", file=sys.stderr)
        print(f"  {etape:22s} {len(FAITS) - avant:5d} faits", file=sys.stderr)
    # Un seul parcours de la collecte pour les deux listes : celle de l'outil,
    # cherchée à chaque fois, et celle de l'analyste quand il en donne une.
    avant = len(FAITS)
    demandes = lire_indicateurs(args.indicateurs) if args.indicateurs else []
    tous = interets() + demandes
    # La signature couvre la collecte ET les questions posées : reprendre un
    # journal établi pour d'autres indicateurs rendrait des réponses à des
    # questions qu'on ne pose plus.
    signature = hashlib.sha256(
        json.dumps([os.path.abspath(args.collecte)]
                   + sorted(f"{x['genre']}:{x['valeur']}" for x in tous)).encode()
    ).hexdigest()
    journal = os.path.splitext(args.sortie)[0] + "-reprise.jsonl"
    rep = Reprise(journal, signature)
    if args.sans_reprise:
        with contextlib.suppress(OSError):
            os.unlink(journal)
    elif rep.charger():
        print(f"  reprise : {len(rep.connus)} fichiers déjà parcourus, relus depuis "
              f"{os.path.basename(journal)}", file=sys.stderr)
    try:
        indicateurs(c, tous, args.indicateurs, rep.ouvrir())
    finally:
        rep.fermer()
    print(f"  {'indicateurs et intérêts':22s} {len(FAITS) - avant:5d} faits",
          file=sys.stderr)

    with open(args.sortie, "w", encoding="utf-8") as fh:
        for f in FAITS:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    ecrire_csv(os.path.splitext(args.sortie)[0] + ".csv", FAITS, COLONNES_CSV)

    chemin_man = os.path.splitext(args.sortie)[0] + "-manifeste.json"
    with open(chemin_man, "w", encoding="utf-8") as fh:
        man = manifeste(c, args.sortie, sys.argv)
        json.dump(man, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")

    par_cat = man["faits"]["par_categorie"]
    print(f"\n{len(FAITS)} faits → {args.sortie}  (+ .csv)", file=sys.stderr)
    print(f"  empreintes des pièces lues → {chemin_man}", file=sys.stderr)
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(par_cat.items())),
          file=sys.stderr)


if __name__ == "__main__":
    main()
