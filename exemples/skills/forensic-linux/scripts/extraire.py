#!/usr/bin/env python3
"""Extrait des FAITS datés et sourcés d'une collecte tasker.sh collecte-linux.

    extraire.py <dossier de collecte> [-o faits.jsonl]

Chaque fait porte d'où il vient et comment il a été obtenu : un lecteur doit
pouvoir refaire le geste à la main. Rien n'est interprété ici — le tri, le
recoupement et le jugement sont le travail du rapport.

Bibliothèque standard seulement. La collecte n'est jamais modifiée : les
archives sont lues en flux, jamais dépaquetées sur place.
"""
import argparse, bisect, bz2, codecs, collections, contextlib, csv, fnmatch, gzip
import hashlib, io, json, lzma, os, re
import urllib.parse
import sqlite3, struct, sys, tarfile, tempfile, zlib
from datetime import datetime, timedelta, timezone

# Les colonnes de tête, dans l'ordre où on les lit. Les champs nommés en plus
# par les faits (tty, vid, premiere, porte…) viennent ensuite, tout seuls : les
# déclarer à la main faisait disparaître du CSV, sans un mot, tout ce qu'on
# ajoutait ensuite au JSONL — et c'est justement là que sont les synthèses.
COLONNES_CSV = ("id", "categorie", "fait", "valeur", "horodatage", "acteur", "confiance",
                "source", "methode", "note")

FAITS = []


# Ces dossiers ne portent pas des FICHIERS mais des octets récupérés : ni date,
# ni chemin d'origine, ni compte. Une adresse qui n'en sort que n'est jamais
# mieux qu'« à vérifier », quelle que soit la confiance du fait qui la porte —
# celui-ci est sûr de l'avoir LUE, pas de ce qu'elle signifie.
#
# C'est le DOSSIER qui décide, et non la catégorie du fait : un indicateur
# demandé par l'analyste et trouvé dans un strings de disque n'est pas mieux
# daté qu'une chaîne quelconque, alors que la même recherche dans un profil
# réseau, elle, désigne une configuration.
#
# fait() le stamppe à la CRÉATION, dans un champ « provenance » qui sort au
# JSONL et au CSV. Le laisser à la charge de qui relit les faits voulait dire
# le redéduire d'une comparaison de chemins dans chaque synthèse, sans que le
# lecteur du rapport, lui, puisse jamais le voir.
DOSSIERS_SANS_PROVENANCE = ("STRINGS/", "PHOTOREC/", "SUPPRIMES/")


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


def _coupe(v, n):
    """Une valeur coupée le DIT, par un « … » à l'endroit du couteau.

    Sans cette marque, une ligne de cron de trois cents octets et une de cent
    se lisent pareil dans le JSONL, dans le CSV et dans le rapport : l'analyste
    cite une phrase que l'outil a raccourcie sans le signaler.

    Et une adresse collée au bout d'une valeur coupée est un PIÈGE : un
    « ExecStart=/usr/bin/curl https://collecteur.example/tres/long/chemin »
    tranché à 140 caractères rend un hôte qui n'a jamais existé. La synthèse
    des adresses se sert de ce « … » pour écarter ce qui touche la coupure.
    """
    return v if len(v) <= n else v[:n] + "…"


def fait(categorie, quoi, valeur, source, methode, horodatage=None, acteur=None,
         confiance="certaine", note=None, **champs):
    """Pose un fait. source = chemin dans la collecte ; methode = le geste.

    Les champs nommés en plus (tty, origine, fin, cible…) sont des données
    structurées : ce que le rapport doit pouvoir lire sans relire une phrase.

    Un fait tiré d'un dossier de récupération porte « provenance » : ces
    pièces-là sont des octets, pas des fichiers, et rien de ce qu'on y lit
    n'est datable ni imputable. Le poser ICI plutôt que dans chaque relecteur
    le rend visible au lecteur du rapport, et impossible à oublier.
    """
    f = {"id": f"F{len(FAITS) + 1:04d}", "categorie": categorie, "fait": quoi,
         "valeur": valeur, "source": source, "methode": methode}
    provenance = ("octets récupérés : ni fichier d'origine, ni date, ni compte"
                  if str(source).startswith(DOSSIERS_SANS_PROVENANCE) else None)
    for k, v in (("horodatage", horodatage), ("acteur", acteur),
                 ("confiance", confiance), ("note", note),
                 ("provenance", provenance), *champs.items()):
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

    def __init__(self, racine):
        self.racine = os.path.abspath(racine)
        self.prefix = os.path.basename(self.racine)
        self.lus = set()          # ce qui a servi, pour le manifeste
        self.mtimes = {}          # archive → {membre: date}, rempli en lisant
        self.abimees = set()      # archives dont la lecture s'est arrêtée net
        if not os.path.isdir(self.racine):
            sys.exit(f"pas un dossier : {self.racine}")
        # os-release, lu une fois : les faits « machine » en viennent, et la
        # famille du système décide de ce qui est normal ou non, dès la
        # vérification de complétude
        self.os_release = self.un("os-release", "SYSTEME")
        champs = _champs(self.texte(self.os_release)) if self.os_release else {}
        self.familles = {x.lower() for k in ("ID", "ID_LIKE") for x in champs.get(k, "").split()}

    def rel(self, chemin):
        """Le chemin tel qu'il sera CITÉ : jamais celui par lequel on ouvre.

        Le repli des demi-codets a donc lieu ici, une fois pour toutes — et
        non à chaque écriture. Le journal de reprise, le manifeste et les
        sources des faits portent alors tous la même chaîne, écrivable."""
        return _propre(os.path.relpath(chemin, self.racine))

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

    def lignes_texte(self, chemin, limite=8_000_000, bloc=1 << 20):
        """Les mêmes lignes que texte(...).splitlines(), SANS le fichier entier.

        texte() lit jusqu'à sa limite d'un seul coup puis décode : pour le
        journal du poste, dont la limite est de 400 Mo, cela fait coexister
        les octets, la chaîne décodée et la liste des lignes — mesuré 1034 Mio
        de pic pour un journal de 392 Mo, soit deux fois et demie la pièce,
        alors qu'on n'en tire que sept faits.

        La découpe est celle de str.splitlines, et non celle de l'itération
        d'un fichier texte : le journal d'un poste porte des octets de
        contrôle, et str.splitlines coupe AUSSI sur \v, \f, \x85, U+2028 et
        U+2029. Lire ligne à ligne avec « for l in fh » aurait rendu d'autres
        lignes, donc d'autres faits, sur les seuls journaux qui en portent.

        On garde donc le dernier morceau d'un bloc pour le recoller au suivant
        — une ligne à cheval, ou un « \r » suivi d'un « \n » au bloc d'après.
        """
        self.lus.add(chemin)
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        reste, lus = "", 0
        try:
            with open(chemin, "rb") as fh:
                while lus < limite:
                    brut = fh.read(min(bloc, limite - lus))
                    if not brut:
                        break
                    lus += len(brut)
                    morceaux = (reste + dec.decode(brut)).splitlines(True)
                    reste = morceaux.pop() if morceaux else ""
                    for x in morceaux:
                        yield x.splitlines()[0]
        except OSError:
            return
        for x in (reste + dec.decode(b"", True)).splitlines():
            yield x

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
        except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
            # Un mot sur stderr ne suffit PAS : le rapport est bâti sur les
            # faits, et il ne portait aucune trace que var/log/secure et
            # var/log/messages n'avaient jamais été lus. Une archive tronquée
            # rendait donc une collecte SILENCIEUSEMENT incomplète — et
            # « journaux 0 faits » se lit comme « rien à signaler ».
            # Une fois par archive : dates_tar() la reparcourt.
            print(f"  ! archive illisible {os.path.basename(archive)} : {e}",
                  file=sys.stderr)
            if archive not in self.abimees:
                self.abimees.add(archive)
                fait("limite", "archive lue en partie seulement", self.rel(archive),
                     self.rel(archive), f"{type(e).__name__} pendant le parcours",
                     confiance="certaine",
                     note="les membres qui suivent le point de rupture ne sont "
                          "PAS dans l'analyse ; le compte de faits de cette "
                          "phase ne vaut pas pour toute l'archive")


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
    # « role » est un nom de MACHINE, que la synthèse et le brouillon peuvent
    # reconnaître. Le libellé en français, lui, est du texte de rapport : le
    # reformuler ne doit pas vider le tableau des supports sans un mot d'erreur,
    # ce qui arrivait quand trois endroits sélectionnaient sur la phrase.
    ("support", "support amovible USB branché", 'New USB device',
     re.compile(r'usb\s+([\d.-]+):\s+New USB device found,\s*(.*)$'),
     lambda m: (None, f"port {m.group(1)}, {m.group(2).strip()}",
                {"role": "usb-branchement"})),
    # Le numéro de série est LA pièce d'identité du support : c'est lui qui
    # permet de dire que la même clé a servi sur une autre machine. Il ne doit
    # pas partager son étiquette avec le modèle.
    ("support", "numéro de série du support USB", 'SerialNumber',
     re.compile(r'usb\s+[\d.-]+:\s+SerialNumber:\s*(.+)$'),
     lambda m: (None, m.group(1).strip(), {"role": "usb-serie"})),
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
    # Le préfixe de commande est tombé : « systemd[1]: Mounted
    # /run/media/mrobert/CLE. » ne porte ni « mount », ni « gvfs », ni
    # « udisks », et ce montage-là n'était jamais vu — alors que le skill
    # conformite le voyait, sur le MÊME journal. Le chemin /run/media/<compte>/
    # est à lui seul la signature, et le crible « /media/ » borne le coût.
    # Le compte est dans le chemin — c'est l'attribution la plus directe qui
    # existe pour un support amovible.
    ("support", "système de fichiers amovible monté", '/media/',
     re.compile(r'((?:/run)?/media/([^/\s]+)/[^\s,;:]*[^\s,;:.])'),
     lambda m: (m.group(2), m.group(1), {"role": "montage-amovible"})),
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
# Une ligne syslog porte l'heure du POSTE, le mtime du fichier est en UTC :
# les comparer demande de tolérer l'écart des fuseaux, de −12 à +14 heures.
MARGE_FUSEAU = timedelta(hours=26)
RE_SYSLOG = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$')


def _ligne_journal(ligne, fin_fichier=None):
    """(horodatage ISO ou None, reste de la ligne, année devinée ?).

    Une ligne syslog — « Jan  8 14:02:11 poste sshd[900]: … » — ne porte PAS
    l'année. Sans elle, la ligne n'est pas datable, et c'est le format
    principal de Debian, d'Ubuntu et de RHEL avant le tout-journal.
    On prend alors l'année qui place la ligne juste avant la dernière écriture
    du fichier : logrotate garantit qu'un journal couvre moins d'un an, donc
    une seule année convient. C'est une déduction, elle est marquée comme telle.

    Elle ne porte pas non plus de FUSEAU : c'est l'heure du poste, lue sur son
    horloge. L'horodatage sort donc SANS suffixe — ni « Z », ni décalage —,
    comme le fait déjà « dpkg.log ». Le marquer « Z » revenait à affirmer de
    l'UTC : sur un poste à Paris, une ligne de 09:00:01 ressortait en
    09:00:01Z, c'est-à-dire 10:00:01 heure du poste, à côté de faits
    journalctl correctement décalés. Deux échelles dans le même fichier de
    faits, sans que rien ne le dise.

    La MARGE de la comparaison vient du même défaut. « fin_fichier » est le
    mtime du fichier, lui en UTC : à l'est de Greenwich, l'heure locale des
    dernières lignes DÉPASSE ce mtime, l'année courante était rejetée, et
    c'est l'année précédente qui sortait — une date fausse d'un an, sur les
    lignes les plus récentes, donc celles qui intéressent l'enquête. Vingt-six
    heures couvrent tous les fuseaux (−12 à +14) et la seconde intercalaire.
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
    borne = fin_fichier.replace(tzinfo=None) + MARGE_FUSEAU
    for annee in (fin_fichier.year, fin_fichier.year - 1):
        try:
            d = datetime(annee, mois, int(m.group(2)), h, mn, sec)
        except ValueError:
            continue
        if d <= borne:
            return d.isoformat(), m.group(5), True
    return None, m.group(5), False


def journal(source_rel, contenu, methode, fin_fichier=None):
    # une chaîne (un membre d'archive déjà en mémoire) ou un flux de lignes
    # (le journal du poste, qui pèse des centaines de mégaoctets)
    for ligne in (contenu.splitlines() if isinstance(contenu, str) else contenu):
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
        journal(c.rel(j), c.lignes_texte(j, 400_000_000),
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
def _base_muette(source, quoi, e):
    """Une base de navigateur qui ne rend rien doit le DIRE.

    Une base abîmée, chiffrée, ou dont le schéma a changé — Chrome renomme ses
    tables d'une version à l'autre — rendait zéro ligne en silence, et le
    rapport se lisait « aucun historique » pour un profil qui était là, sous les
    yeux. C'est le contresens le plus coûteux que ce script puisse produire :
    une absence de preuve présentée comme une preuve d'absence.
    """
    if source:
        fait("limite", f"base de navigateur illisible : {quoi}", source, source,
             "sqlite3 sur une copie en lecture seule", confiance="certaine",
             note=f"{type(e).__name__} : {e}. Ce qu'elle contenait n'est PAS "
                  "dans l'analyse — ne lisez pas son silence comme une absence "
                  "de navigation")


@contextlib.contextmanager
def _sqlite(blob, source=None):
    """Une base sqlite copiée hors des scellés, ouverte immuable : rien n'est
    jamais écrit dans la pièce, pas même un journal -wal."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(blob)
        tmp.flush()
        try:
            cx = sqlite3.connect(f"file:{tmp.name}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error as e:
            _base_muette(source, "base non ouvrable", e)
            yield None
            return
        try:
            yield cx
        finally:
            cx.close()


def _lignes(cx, sql, params=(), source=None, quoi=None):
    if cx is None:
        return []
    try:
        return cx.execute(sql, params).fetchall()
    except sqlite3.Error as e:
        _base_muette(source, f"requête « {quoi or sql[:40]} » impossible", e)
        return []


def _flux(cx, sql, params=(), source=None, quoi=None):
    """Les mêmes lignes que _lignes, mais RENDUES AU FIL DE L'EAU.

    L'historique n'est pas borné — c'est une exigence du skill —, et un profil
    de plusieurs années compte des centaines de milliers de pages. fetchall()
    en fait une liste de tuples que l'on parcourt UNE fois pour poser un fait
    par ligne : la liste entière n'existe que pour être jetée, et elle double
    le pic mémoire de la phase.

    Le tri, l'ordre et donc les identifiants des faits sont ceux de la
    requête : c'est la même, rendue autrement.

    Une base ABÎMÉE se comporte autrement, et c'est la seule différence :
    fetchall() rendait tout ou rien, ici les lignes déjà lues sont déjà des
    faits. Sur une pièce forensique, garder ce qui a pu être lu vaut mieux que
    de tout jeter — mais cela se DIT, plutôt que de se découvrir.
    """
    if cx is None:
        return
    try:
        curseur = cx.execute(sql, params)
        while True:
            lot = curseur.fetchmany(512)
            if not lot:
                return
            yield from lot
    except sqlite3.Error as e:
        _base_muette(source, f"lecture « {quoi or sql[:40]} » interrompue", e)
        return


def _sqlite_lire(blob, requetes, source=None):
    """(nom, lignes) pour chaque requête d'une même base."""
    with _sqlite(blob, source) as cx:
        for nom, sql in requetes:
            lignes = _lignes(cx, sql, source=source, quoi=nom)
            if lignes:
                yield nom, lignes


# RIEN n'est borné ici : tout ce que la base porte devient un fait. Un profil
# de plusieurs années compte des dizaines de milliers de pages, et une borne
# aurait beau se dire dans un fait « limite », elle laisserait dehors les plus
# ANCIENNES — c'est-à-dire justement ce qu'on ne peut retrouver nulle part
# ailleurs quand l'historique récent a été vidé. Chaque page porte son nombre
# de visites et la première : ce qui distingue un passage d'une habitude.
FF_EPOCH = "datetime(v.last_visit_date/1000000,'unixepoch')"
REQ_FIREFOX = {
    "visite": f"SELECT {FF_EPOCH}, v.url, v.title, v.visit_count, "
              "(SELECT datetime(MIN(h.visit_date)/1000000,'unixepoch') "
              " FROM moz_historyvisits h WHERE h.place_id=v.id) "
              "FROM moz_places v WHERE v.last_visit_date IS NOT NULL "
              "ORDER BY v.last_visit_date DESC",
    "telechargement":
        "SELECT datetime(a.dateAdded/1000000,'unixepoch'), a.content, p.url "
        "FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
        "WHERE a.content LIKE 'file://%' ORDER BY a.dateAdded DESC",
    # un marque-page est un choix délibéré, et il est DATÉ : il survit au
    # vidage de l'historique, que l'utilisateur croit souvent suffisant
    "marque-page":
        "SELECT datetime(b.dateAdded/1000000,'unixepoch'), p.url, b.title "
        "FROM moz_bookmarks b JOIN moz_places p ON p.id=b.fk "
        "WHERE b.type=1 AND p.url NOT LIKE 'place:%' "
        "ORDER BY b.dateAdded DESC",
}
# Un cookie prouve une visite même quand l'historique a été vidé : les deux
# bases sont indépendantes. On regroupe par domaine — un profil en compte des
# milliers — et on ne sort JAMAIS la colonne « value » : c'est un jeton de
# session, donc un identifiant réutilisable. Le domaine et les dates suffisent
# à établir la visite ; la valeur n'ajoute rien et ferait du rapport un secret.
REQ_COOKIES_FF = [
    ("cookie", "SELECT host, COUNT(*), MIN(creationTime), MAX(lastAccessed) "
               "FROM moz_cookies GROUP BY host ORDER BY MAX(lastAccessed) DESC"),
    ("cookie (ancien schéma)",
     "SELECT baseDomain, COUNT(*), MIN(creationTime), MAX(lastAccessed) "
     "FROM moz_cookies GROUP BY baseDomain ORDER BY MAX(lastAccessed) DESC"),
]

# Chrome range ses cookies dans « Cookies » — sous Default/, ou sous
# Default/Network/ depuis Chrome 96. Mêmes colonnes utiles que Firefox, mais
# l'époque est celle de 1601. La valeur y est chiffrée par le trousseau du
# bureau : illisible sans la clé, et on ne la lit pas davantage.
REQ_COOKIES_CHROME = [
    ("cookie", "SELECT host_key, COUNT(*), MIN(creation_utc), MAX(last_access_utc) "
               "FROM cookies GROUP BY host_key ORDER BY MAX(last_access_utc) DESC"),
]

REQ_CHROME = {
    "visite": "SELECT datetime(u.last_visit_time/1000000-11644473600,'unixepoch'), "
              "u.url, u.title, u.visit_count, "
              "(SELECT datetime(MIN(x.visit_time)/1000000-11644473600,'unixepoch') "
              " FROM visits x WHERE x.url=u.id) "
              "FROM urls u WHERE u.last_visit_time > 0 "
              "ORDER BY u.last_visit_time DESC",
    "telechargement":
        "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url "
        "FROM downloads ORDER BY start_time DESC",
    # ce que le compte a TAPÉ dans la barre d'adresse : l'intention, pas
    # seulement la page atteinte
    "recherche":
        "SELECT datetime(u.last_visit_time/1000000-11644473600,'unixepoch'), k.term, u.url "
        "FROM keyword_search_terms k JOIN urls u ON u.id=k.url_id "
        "ORDER BY u.last_visit_time DESC",
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
    for _, lignes in _sqlite_lire(blob, requetes, source):
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
    for _, lignes in _sqlite_lire(blob, req, source):
        for site, cree, vu in lignes:
            fait("usage", "mot de passe enregistré dans le navigateur", site, source,
                 "colonne origin_url de la table logins (identifiant et mot de passe non lus)",
                 horodatage=_date_us(vu, True), acteur=compte,
                 note=f"enregistré le {_date_us(cree, True)}" if cree else None)


def _historique_navigateur(source, compte, blob, req, outil):
    with _sqlite(blob, source) as cx:
        # _flux et non _lignes : c'est la seule requête sans borne de la
        # collecte, et la seule dont la liste complète ne servirait à rien
        for ts, url, titre, combien, premiere in _flux(cx, req["visite"], source=source, quoi="visite"):
            ts, premiere = _iso_z(ts), _iso_z(premiere)
            note = f"{combien} visite(s)" if combien else ""
            if premiere and premiere != ts:
                note += f", la première le {premiere}"
            if titre:
                note = f"{note} — {titre}" if note else titre
            fait("navigation", "page visitée", url, source,
                 f"sqlite3 sur l'historique {outil}", horodatage=ts, acteur=compte,
                 note=note or None)
        for ts, cible, origine in _lignes(cx, req["telechargement"], source=source, quoi="téléchargement"):
            fait("telechargement", "fichier téléchargé", cible, source,
                 f"sqlite3 sur les téléchargements {outil}", horodatage=_iso_z(ts),
                 acteur=compte, note=f"depuis {origine}" if origine else None)
        for ts, url, titre in (_lignes(cx, req["marque-page"], source=source, quoi="marque-page")
                               if req.get("marque-page") else []):
            fait("navigation", "marque-page enregistré", url, source,
                 f"sqlite3 sur les marque-pages {outil}", horodatage=_iso_z(ts),
                 acteur=compte, note=(titre or None),
                 confiance="certaine")
        for ts, terme, url in (_lignes(cx, req["recherche"], source=source, quoi="recherche")
                               if req.get("recherche") else []):
            fait("navigation", "recherche saisie dans la barre d'adresse", terme, source,
                 f"sqlite3 sur keyword_search_terms {outil}", horodatage=_iso_z(ts),
                 acteur=compte, confiance="forte",
                 note=(f"a mené à {url}. " if url else "")
                      + "la date est celle de la DERNIÈRE visite de la page atteinte, "
                        "pas celle de la frappe : une recherche ancienne dont la page a "
                        "été revue porte la date récente")



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
                   "FROM moz_formhistory ORDER BY lastUsed DESC"),
]
# Chrome compte en SECONDES dans cette table — pas en microsecondes comme
# ailleurs : c'est la table, pas une devinette.
REQ_FORMULAIRES_CHROME = [
    ("formulaire", "SELECT name, value, count, "
                   "datetime(date_created,'unixepoch'), datetime(date_last_used,'unixepoch') "
                   "FROM autofill ORDER BY date_last_used DESC"),
]


def _formulaires(source, compte, blob, req, outil):
    for _, lignes in _sqlite_lire(blob, req, source):
        for champ, valeur, combien, premier, dernier in lignes:
            fait("usage", "saisie dans un formulaire", _coupe(str(valeur), 200), source,
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
    while pile:
        noeud, dossier = pile.pop()
        for enfant in noeud.get("children", []) or []:
            if enfant.get("type") == "folder":
                pile.append((enfant, enfant.get("name") or dossier))
            elif enfant.get("url"):
                quand = enfant.get("date_added")
                fait("navigation", "marque-page enregistré", enfant["url"], source,
                     "lecture du fichier Bookmarks (JSON)", acteur=compte,
                     horodatage=_date_us(int(quand), True) if str(quand).isdigit() else None,
                     note=f"« {enfant.get('name', '')} », dans « {dossier} »")


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


def _base_navigateur(source, compte, base, blob):
    """Un membre d'archive dont le nom est dans NAVIGATEURS — ou son -wal."""
    if base in NAVIGATEURS:
        outil, req, traitement = NAVIGATEURS[base]
        if traitement == "historique":
            _historique_navigateur(source, compte, blob, req, outil)
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
                    _base_navigateur(source, compte, base, blob)
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
                 f"{os.path.basename(nom)} : {_coupe(commande, 140)}", source,
                 "ExecStart= de l'unité systemd",
                 confiance="à vérifier" if anormal else "certaine",
                 note="une unité livrée par un paquet lance depuis /usr ; "
                      "celle-ci ne le fait pas" if anormal else
                      "posée à la main ou par un installeur, pas par le gestionnaire "
                      "de paquets")
    elif nom.endswith(".desktop") and "autostart" in nom:
        for m in re.finditer(r'^\s*Exec\s*=\s*(.+)$', txt, re.M):
            fait("persistance", "programme lancé à l'ouverture de session",
                 f"{os.path.basename(nom)} : {_coupe(m.group(1).strip(), 140)}", source,
                 "Exec= du fichier .desktop d'autostart", confiance="certaine")
    elif nom.endswith(".rules") and "udev" in nom:
        for m in RE_RUN_UDEV.finditer(txt):
            fait("persistance", "règle udev lançant un programme",
                 f"{os.path.basename(nom)} : {_coupe(m.group(1).strip(), 140)}", source,
                 "RUN+= d'une règle udev", confiance="à vérifier",
                 note="se déclenche au branchement d'un matériel")
    elif os.path.basename(nom) in ("rc.local",) or "/profile.d/" in nom:
        for l in txt.splitlines():
            l = l.strip()
            if l and not l.startswith("#") and LIEU_ANORMAL.search(l):
                fait("suspect", "commande lancée au démarrage depuis un endroit anormal",
                     f"{os.path.basename(nom)} : {_coupe(l, 140)}", source,
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
        # Une ligne commençant par « # » n'est PAS écartée : RE_HISTO_EPOCH
        # attrape déjà les marqueurs de date, et le reste, bash l'a enregistré
        # parce que l'utilisateur l'a TAPÉ. Le skill conformite les gardait :
        # les deux rapports annonçaient des comptes différents pour le même
        # fichier, et une commande commentée — « # curl http://x | bash » —
        # échappait entièrement au balayage des motifs suspects.
        if l.strip():
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
                 f"{base} : {_coupe(m.group(1).strip(), 140)}", source,
                 "Exec= d'un .desktop de ~/.config/autostart", acteur=compte,
                 confiance="certaine",
                 note="propre à ce compte : il se lance quand il ouvre sa session")
    elif base == "authorized_keys" and txt.strip():
        for l in txt.splitlines():
            if l.strip() and not l.startswith("#"):
                fait("suspect", "clé SSH autorisée à ouvrir ce compte", _coupe(l.strip(), 120),
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
            if RE_RETRAIT.search(l):
                m = re.match(r'^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)', l)
                fait("paquet", "paquet retiré", _coupe(l.strip(), 160),
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
_GENRE_CHAINE = {
    "urls": "adresse web",
    "courriels": "adresse de courriel",
    "ip": "adresse IP",
    "mac": "adresse MAC",
    "chemins": "chemin personnel",
}
# Le fichier brut et ses extraits portent la MÊME extension. C'est donc le
# genre, pris dans la liste connue, qui les départage — et lui seul : avec un
# « [a-z]+ » quelconque, un volume nommé « home_data » se lirait comme un
# extrait de genre « data », et « .+ » glouton ferait passer tous les extraits
# pour des fichiers bruts. On essaie donc l'extrait d'abord, sur un genre connu.
RE_EXTRAIT = re.compile(r'_strings_(?P<volume>.+)_(?P<genre>'
                        + "|".join(_GENRE_CHAINE) + r')\.txt$')
RE_BRUT = re.compile(r'_strings_(?P<volume>.+)\.txt$')
_SANS_DATE = ("lu sur les OCTETS du disque : ni date, ni fichier d'origine, ni "
              "compte, et — strings étant appelé nu — sans le décalage qui "
              "situerait l'occurrence sur le volume. Une chaîne présente ici a "
              "existé sur ce volume, c'est tout ce qu'elle établit")


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
        # L'extrait d'ABORD : lui seul porte un genre connu, et le motif du
        # fichier brut, plus large, l'avalerait.
        m = RE_EXTRAIT.search(f)
        if not m:
            brut = RE_BRUT.search(f)
            if brut:
                # Rapporté sur ses PROPRES preuves : un fichier brut dont les
                # extraits manquent est justement le cas qu'il faut signaler.
                fait("chaines", "chaînes brutes du périphérique", brut.group("volume"),
                     c.rel(chemin), "strings sur le périphérique",
                     note=f"{_taille(os.path.getsize(chemin))} de texte brut. "
                          "strings est appelé NU : les chaînes n'y portent pas leur "
                          "décalage en octets, et la longueur minimale est celle par "
                          "défaut — il y a donc beaucoup de bruit binaire. "
                          "Cherchez-y avec --indicateurs")
            continue
        volume, genre = m.group("volume"), m.group("genre")
        libelle = _GENRE_CHAINE.get(genre, genre)
        methode = f"strings sur le périphérique de {volume}, motif « {genre} »"
        # c.lignes et non c.texte : ce dernier coupe à 8 Mo SANS LE DIRE, et
        # l'extrait d'un vrai disque les dépasse — le nombre rapporté serait
        # alors celui des huit premiers mégaoctets, dans une pièce dont le
        # nombre est tout l'intérêt.
        # « <compte> <chaîne> », ce que rend « uniq -c ». Pas de décalage :
        # strings est appelé nu, donc sans -t d. Pour situer une occurrence, il
        # faut revenir au fichier brut et l'y chercher — le fait le dit.
        tete, total = [], 0
        for l in c.lignes(chemin):
            ch = l.strip().split(None, 1)
            if len(ch) != 2 or not ch[0].isdigit() or not ch[1]:
                continue                       # ligne de total, ou ligne vide
            total += 1
            if len(tete) < 20:
                tete.append((int(ch[0]), ch[1]))
        if not total:
            continue
        fait("chaines", f"chaînes distinctes de type « {libelle} »", str(total),
             c.rel(chemin), methode, nature="compte", genre=genre, note=_SANS_DATE)
        for n, valeur in tete:
            fait("chaines", libelle, valeur, c.rel(chemin), methode,
                 confiance="forte", genre=genre, occurrences=n, volume=volume,
                 note=f"{n} occurrence(s) dans les octets du volume {volume} — non "
                      "datée, non imputable, et sans position sur le volume : pour "
                      "la situer, cherchez-la dans le fichier de chaînes brutes. "
                      "À recouper avec une pièce qui, elle, porte une date")
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
        elif f.get("role") == "montage-amovible":
            montages.append((str(f["valeur"]).rstrip("/"), f))
    return fichiers, montages


# Le motif est écrit en MINUSCULES et se cherche sur un chemin abaissé, plutôt
# que d'employer re.I : le moteur replie sinon chaque caractère qu'il compare,
# sur chaque ligne d'une timeline qui en compte des millions. Mesuré sur
# 500 000 chemins : 627 ns la ligne avec re.I, 395 sans — un tiers de moins,
# pour exactement les mêmes trouvailles.
#
# « /root/ » écrit à l'intérieur de la parenthèse aurait demandé « //root/ » :
# elle s'ouvre déjà après une barre oblique. Le dossier de l'administrateur
# était donc INATTEIGNABLE.
SENSIBLES = re.compile(r'/(\.ssh/|downloads?/|t[ée]l[ée]chargements?/|media/|run/media/'
                       r'|tmp/\.|\.bash_history|authorized_keys|root/)')


def _chemin_annonce(f):
    """Le chemin absolu qu'un fait annonce, en minuscules — ou None.

    Un téléchargement et un « fichier ouvert récemment » portent tous deux le
    chemin COMPLET : « file:///home/jdupont/Téléchargements/facture.pdf ». La
    timeline peut donc être interrogée sur le chemin, et pas seulement sur le
    nom.
    """
    v = urllib.parse.unquote(str(f.get("valeur") or ""))
    if v.lower().startswith("file://"):
        v = urllib.parse.urlparse(v).path
    return v.rstrip("/").lower() if v.startswith("/") else None


def timeline(c):
    chemin = c.un("_mactime.csv", "TIMELINE")
    if not chemin:
        return
    tz = c.un("_fuseau_timeline.txt", "TIMELINE")
    fuseau = c.texte(tz).strip() if tz else None
    fichiers, montages = _questions_timeline()
    # Les chemins que les faits demandeurs annoncent : un emplacement qui
    # correspond EXACTEMENT à l'un d'eux ne doit jamais être évincé par le
    # plafond des trois emplacements cités.
    annonces = {a for demandeurs in fichiers.values()
                for a in (_chemin_annonce(x) for x in demandeurs) if a}
    trouves, sous_montage = {}, {}
    # Ce qui a été VU, par opposition à ce qui a été cité : sans ce compte, un
    # plafond atteint ne se distingue pas d'une absence, et le rapport annonce
    # « 3 emplacements portent ce nom » quand il y en a trente.
    combien, coupes = collections.Counter(), {}
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
            if not any(x[3] == fichier for x in ou):
                combien[base] += 1
                if len(ou) < 3:
                    ou.append((quand, genre, inode, fichier))
                elif fichier.lower() in annonces:
                    # Le chemin ANNONCÉ passe devant : le plafond évinçait
                    # justement l'emplacement pour lequel la question était
                    # posée, dès que trois homonymes le précédaient.
                    ou[-1] = (quand, genre, inode, fichier)
        for prefixe, _ in montages:
            if fichier.startswith(prefixe + "/"):
                vise = True
                liste = sous_montage.setdefault(prefixe, [])
                coupes[prefixe] = coupes.get(prefixe, 0) + 1
                if len(liste) < MAX_PAR_SUPPORT:
                    liste.append((quand, genre, fichier))
        # la pêche large ne redit pas ce qu'une question précise dira mieux
        if not vise and SENSIBLES.search(fichier.lower()):
            vus += 1
            if vus > MAX_SENSIBLES:
                continue
            fait("timeline", "activité sur un chemin sensible", fichier, c.rel(chemin),
                 "chemins d'intérêt dans la timeline mactime",
                 horodatage=_date_timeline(quand, fuseau), genre=genre, inode=inode or None,
                 note=f"{genre} — {_GENRES.get(genre.replace('.', '') or '', 'dates du fichier')}")

    fait("timeline", "entrées dans la timeline du système de fichiers",
         str(max(0, total - 1)), c.rel(chemin), "mactime -b corps -d -y, puis wc -l",
         note="corps lus sur le périphérique quand un lecteur existait"
              + (f" ; dates écrites dans le fuseau {fuseau}" if fuseau else
                 " ; fuseau de la timeline inconnu — TZ_MACTIME n'a pas été relevé"))

    # Trois plafonds mordaient en SILENCE. Un plafond tu se lit comme une
    # absence : « 40 fichiers sur la clé » et « les 40 premiers sur 3 000 » ne
    # disent pas la même chose, et c'est la seconde phrase qui est vraie.
    if vus > MAX_SENSIBLES:
        fait("limite", "chemins sensibles : le plafond de citation est atteint",
             str(vus), c.rel(chemin), "chemins d'intérêt dans la timeline mactime",
             note=f"{vus} entrées correspondent, {MAX_SENSIBLES} sont citées. Les "
                  "suivantes ne sont PAS dans l'analyse : resserrez la question, "
                  "ou relisez la timeline sur le chemin qui vous intéresse")
    for prefixe, n in sorted(coupes.items()):
        if n > MAX_PAR_SUPPORT:
            fait("limite", "support amovible : le plafond de citation est atteint",
                 prefixe, c.rel(chemin), f"chemins sous « {prefixe}/ » dans la timeline",
                 note=f"{n} entrées sous ce point de montage, {MAX_PAR_SUPPORT} "
                      "citées. Le compte ci-dessus est complet ; la liste ne l'est pas")

    # ── ce que la timeline confirme, ou pas ──
    for base, demandeurs in sorted(fichiers.items()):
        for f in demandeurs:
            if base in trouves:
                annonce = _chemin_annonce(f)
                for quand, genre, inode, fichier in trouves[base]:
                    # Le NOM seul ne fait pas le fichier. « facture.pdf » dans
                    # les téléchargements d'un compte et « facture.pdf » sous
                    # /usr/share/doc portent le même nom et n'ont rien à voir :
                    # le fait sortait pourtant « certaine », avec l'ACTEUR du
                    # fait demandeur, et le rapport attribuait à quelqu'un un
                    # fichier sur une homonymie. Quand le chemin annoncé est
                    # connu, on l'exige ; sinon le fait le dit, ne porte pas
                    # d'acteur, et reste à vérifier.
                    meme = annonce is not None and fichier.lower() == annonce
                    reste = _GENRES.get(genre.replace(".", "") or "", "dates du fichier")
                    if meme:
                        note = (f"{reste} — le fichier annoncé par {f['id']} existe "
                                "bien sur le disque, au chemin annoncé")
                    else:
                        note = (f"{reste} — MÊME NOM que le fichier de {f['id']}"
                                + (f", mais pas le même chemin : {f['id']} annonce "
                                   f"« {annonce} »" if annonce else
                                   f" ({f['id']} n'annonce aucun chemin)")
                                + ". Deux fichiers peuvent porter le même nom sans "
                                  "avoir de rapport : à confirmer par l'inode ou la "
                                  "taille avant d'attribuer celui-ci à qui que ce soit")
                    if combien[base] > 1:
                        note += (f" ; {combien[base]} emplacements portent ce nom"
                                 + (f", dont {len(trouves[base])} cités ici"
                                    if combien[base] > len(trouves[base]) else ""))
                    fait("timeline", "fichier retrouvé sur le disque" if meme
                         else "fichier de MÊME NOM sur le disque",
                         fichier, c.rel(chemin),
                         ("chemin" if meme else "nom") +
                         f" du fichier de {f['id']} cherché dans la timeline",
                         horodatage=_date_timeline(quand, fuseau),
                         acteur=f.get("acteur") if meme else None,
                         confiance="certaine" if meme else "à vérifier",
                         confirme=f["id"], genre=genre, inode=inode or None,
                         note=note)
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
            return _coupe(nue, 160)
    return None


def _apercu(chemin, taille=APERCU):
    """Les premiers octets LISIBLES d'une pièce, sans la lire en entier.

    Une pièce ordinaire se lit telle quelle ; une archive passe par sa
    décompression. On ne passe pas par _blocs, qui sert le chercheur
    d'indicateurs : lui a besoin des octets BRUTS pour calculer une empreinte,
    et lirait donc un .docx de 200 Mo en entier — deux fois — pour rendre ici
    quatre mille octets.
    """
    contenu = _decomprime(chemin, lambda: open(chemin, "rb"), {})
    if contenu is None:
        with open(chemin, "rb") as fh:
            return fh.read(taille)
    morceaux, vus = [], 0
    for m in contenu:
        if not m:
            continue
        morceaux.append(m)
        vus += len(m)
        if vus >= taille:
            break
    return b"".join(morceaux)[:taille]


def _pieces_rendues(c):
    """Les pièces des dossiers de récupération, dans un ordre stable."""
    for dossier in ("PHOTOREC", "SUPPRIMES"):
        base = os.path.join(c.racine, dossier)
        if not os.path.isdir(base):
            continue
        for d, sous, noms in os.walk(base):
            sous.sort()
            noms.sort()
            for f in noms:
                yield os.path.join(d, f)


def documents(c):
    """Les fichiers rendus sans nom, ouverts et caractérisés.

    Ce que la pièce CONTIENT — de quoi ça parle, ce que ça porte. Les motifs
    sensibles qui s'y trouvent ne sont pas cherchés ici : c'est le travail du
    chercheur d'indicateurs, qui parcourt les mêmes dossiers avec la même
    liste. Les chercher aux deux endroits donnait deux réponses différentes,
    puisque l'un lit un aperçu et l'autre le fichier entier — et le rapport
    montrait deux fois la même découverte sous deux intitulés.
    """
    # SUPPRIMES ne vient que de xfs_undelete, et xfs_undelete ne lit QUE de
    # l'xfs. Son absence n'est donc pas un manque de collecte sur un poste en
    # ext4 ou en btrfs : c'est qu'il n'existe pas d'équivalent. Le dire évite
    # qu'un lecteur cherche une pièce qui ne peut pas exister — et évite qu'on
    # la réclame à la collecte.
    if not os.path.isdir(os.path.join(c.racine, "SUPPRIMES")):
        fait("limite", "aucune récupération par les inodes libérés",
             "SUPPRIMES/ absent", c.prefix,
             "présence du dossier produit par xfs_undelete",
             confiance="certaine",
             note="xfs_undelete ne lit QUE de l'xfs : sur ext4, btrfs ou "
                  "tout autre système de fichiers, il n'y a pas "
                  "d'équivalent, et les fichiers récupérés ne viennent "
                  "que de photorec — donc sans inode, sans date, et "
                  "seulement pour les types dont il a la signature. "
                  "Absence normale si le volume n'est pas en xfs ; à "
                  "reprendre s'il l'est")
    rendus, tronque = 0, False
    for chemin in _pieces_rendues(c):
        if rendus >= DOCUMENTS_MAX:
            tronque = True
            break
        try:
            octets = _apercu(chemin)
        except (OSError, zlib.error):
            continue
        texte = _lisible(octets)
        if not texte:
            continue
        porte = []
        if RE_COURRIEL.search(texte) or RE_MAISON.search(texte) \
                or RE_TELEPHONE.search(texte) or RE_REDIGE.search(texte):
            porte.append("utilisateur")
        if RE_SYSTEME.search(texte) or RE_IPV4.search(texte):
            porte.append("système")
        rendus += 1
        fait("document", "fichier rendu sans nom, et lisible",
             _sujet(texte) or "(du texte, sans phrase identifiable)", c.rel(chemin),
             f"ouvert et lu sur ses {_taille(len(octets))} de tête",
             confiance="forte", porte=" / ".join(porte) or "rien de remarquable",
             note="rendu par le carving : ni nom d'origine, ni date, ni compte. "
                  "Ce qu'il contient est établi ; d'où il vient ne l'est pas. "
                  "Les motifs sensibles qu'il porterait sont posés à part, en "
                  "faits « intérêt » sur la même pièce")
    if tronque:
        fait("limite", "documents rendus sans nom : seuls les premiers sont ouverts",
             str(DOCUMENTS_MAX), "PHOTOREC/, SUPPRIMES/",
             f"les {DOCUMENTS_MAX} premiers dans l'ordre des dossiers",
             note="les autres sont comptés par type dans la section des pièces "
                  "récupérées ; pour en ouvrir un précis, cherchez-y avec "
                  "--indicateurs")


# ── 9 ter · la super-timeline de plaso ────────────────────────────────
# psort rend un événement par ligne de JSON. C'est la pièce la plus riche
# d'une collecte : là où mactime ne connaît que les dates du système de
# fichiers, plaso ouvre les bases de navigateur, les journaux, les caches, les
# fichiers de configuration, et rend TOUT sur une seule échelle de temps.
#
# Ce lecteur n'en fait PAS un fait par événement : une super-timeline compte
# des millions de lignes, et les recopier n'apprendrait rien. Il répond à trois
# questions, et c'est tout :
#
#   1. de quoi cette super-timeline est-elle faite — combien d'événements, sur
#      quelle période, par quel analyseur, et pour quelles familles d'artefact ?
#      C'est ce qui dit à l'analyste ce que la pièce PEUT répondre ;
#   2. les fichiers et les points de montage que les autres faits ont déjà mis
#      en question s'y retrouvent-ils — exactement comme timeline() le fait sur
#      mactime, et avec la même exigence de chemin ;
#   3. les chemins sensibles, bornés, et la borne se dit.
#
# Le schéma de « psort -o json_line » a CHANGÉ selon les versions : l'horodatage
# est tantôt « timestamp » en microsecondes, tantôt « date_time.timestamp » en
# secondes, tantôt une chaîne ISO dans « datetime ». Le lecteur accepte les
# trois et COMPTE ce qu'il n'a pas su dater : une ligne muette est un aveu, pas
# un silence.
PLASO_MAX_SENSIBLES = 300
PLASO_TROU_JOURS = 7        # au-delà, un intervalle vide se dit
PLASO_MAX_TROUS = 20


# Le nommage d'une collecte n'est jamais parfait : le dossier peut s'appeler
# PLASO, plaso, Plaso, TIMELINE_PLASO ou rien du tout, et le fichier
# plaso.jsonl, super_timeline.json, l2t.jsonl.gz, PC01-psort.json… On ne se fie
# donc PAS au nom : on retient des candidats bon marché, puis on OUVRE la
# première ligne de chacun et on regarde si c'est du plaso.
_PLASO_NOMS = ("plaso", "l2t", "psort", "log2timeline", "supertimeline",
               "super_timeline", "super-timeline", "timeline")
# Ce qu'une ligne de psort porte, et que rien d'autre ne porte ensemble.
_PLASO_CHAMPS = ("data_type", "timestamp_desc", "parser", "__container_type__",
                 "pathspec", "display_name", "timestamp", "date_time")
# Nos propres sorties : elles portent du JSON par ligne, elles aussi.
_PAS_PLASO = ("faits.jsonl", "constats.jsonl", "-manifeste.json",
              "-reprise.jsonl")


def _plaso_lignes(chemin):
    """Les lignes d'un fichier plaso, comprimé ou non, sans le charger."""
    ouvrir = gzip.open if chemin.lower().endswith(".gz") else open
    try:
        with ouvrir(chemin, "rt", encoding="utf-8", errors="replace") as fh:
            for ligne in fh:
                yield ligne
    except OSError:
        return


def _est_plaso(chemin):
    """Cette pièce est-elle une sortie de psort ? On lit sa PREMIÈRE ligne.

    Deux formes acceptées : « -o json_line », un objet par ligne, et « -o
    json », un unique tableau — dont la première ligne est alors « [ » ou
    « [{… ».
    """
    for ligne in _plaso_lignes(chemin):
        nue = ligne.strip().lstrip("[").rstrip(",")
        if not nue:
            continue
        if not nue.startswith("{"):
            return False
        try:
            e = json.loads(nue.rstrip("]"))
        except json.JSONDecodeError:
            return False
        return (isinstance(e, dict)
                and sum(1 for k in _PLASO_CHAMPS if k in e) >= 2)
    return False


def trouver_plaso(c):
    """Les super-timelines de la collecte, où qu'elles soient rangées.

    On ne descend pas dans les dossiers dont on SAIT ce qu'ils portent — un
    PHOTOREC/ compte des centaines de milliers de fichiers rendus par le
    carving, et aucun n'est une sortie de psort.
    """
    candidats = []
    for chemin in c.chercher(".json"):          # .json ET .jsonl, .gz compris
        base = os.path.basename(chemin).lower()
        rel = c.rel(chemin)
        if any(x in base for x in _PAS_PLASO) or rel.startswith(("PHOTOREC/",
                                                                "SUPPRIMES/")):
            continue
        candidats.append(chemin)
    # Le nom d'abord — un dossier ou un fichier qui se nomme —, le reste
    # ensuite : l'ordre ne change rien au résultat, mais il met les pièces
    # évidentes en tête du rapport.
    nommes = [x for x in candidats
              if any(n in c.rel(x).lower() for n in _PLASO_NOMS)]
    autres = [x for x in candidats if x not in nommes]
    return [x for x in nommes + autres if _est_plaso(x)]


# Un plaso récent sérialise « date_time » comme un objet dfdatetime, et son
# « __class_name__ » dit L'UNITÉ du champ timestamp. Le supposer en secondes —
# ce qui n'est vrai que pour PosixTime — donne une date absurde, et pour
# PosixTimeInMicroseconds une ValueError « year 56014984 is out of range » qui
# emportait la phase entière. (diviseur vers les secondes, origine en secondes
# depuis 1970.)
_1601 = -11644473600            # 1601-01-01, l'origine de Windows
_DFDATETIME = {
    "PosixTime": (1, 0),
    "PosixTimeInMilliseconds": (10 ** 3, 0),
    "PosixTimeInMicroseconds": (10 ** 6, 0),
    "PosixTimeInNanoseconds": (10 ** 9, 0),
    "JavaTime": (10 ** 3, 0),
    "Filetime": (10 ** 7, _1601),          # intervalles de 100 ns
    "WebKitTime": (10 ** 6, _1601),
    "CocoaTime": (1, 978307200),           # 2001-01-01
    "HFSTime": (1, -2082844800),           # 1904-01-01
}
# Hors de ces bornes, ce n'est pas une date : c'est une unité mal devinée.
# Mieux vaut compter la ligne comme NON DATÉE que publier une date fausse — une
# date est ce qu'un rapport cite en premier.
PLASO_MIN, PLASO_MAX = 315532800, 4102444800      # 1980 → 2100


def _plaso_iso(brut):
    """Les secondes depuis 1970 d'une chaîne ISO, ou None."""
    try:
        d = datetime.fromisoformat(brut.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return (d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d).timestamp()


def _plaso_secondes(e):
    """Les secondes depuis 1970 d'un événement plaso, ou None.

    Le « timestamp » de premier niveau est la forme NORMALISÉE de plaso —
    microsecondes depuis 1970 — et c'est la plus sûre : on la préfère. Le
    « date_time » n'est lu qu'à défaut, avec l'unité que sa classe déclare.
    """
    ts = e.get("timestamp")
    if isinstance(ts, (int, float)) and ts:
        # Un seuil grossier distingue les secondes des microsecondes : 10¹² µs
        # font onze jours après 1970, et 10¹² secondes l'an 33658. Aucune date
        # réelle n'est ambiguë.
        return ts / 10 ** 6 if abs(ts) > 10 ** 12 else ts
    dt = e.get("date_time")
    if isinstance(dt, dict):
        brut = dt.get("timestamp")
        if isinstance(brut, (int, float)):
            diviseur, origine = _DFDATETIME.get(str(dt.get("__class_name__")),
                                                (1, 0))
            return brut / diviseur + origine
        # TimeElements et consorts portent une chaîne plutôt qu'un entier.
        if isinstance(dt.get("string"), str):
            return _plaso_iso(dt["string"])
    return None


def _plaso_horo(e):
    """L'horodatage d'un événement plaso, en ISO UTC — ou None."""
    s = _plaso_secondes(e)
    if s is None:
        brut = e.get("datetime")
        s = _plaso_iso(brut) if isinstance(brut, str) and brut else None
    if s is None or not PLASO_MIN <= s <= PLASO_MAX:
        return None
    return _epoch_iso(s)


def _plaso_chemin(e):
    """Le chemin que l'événement désigne. « display_name » porte le préfixe du
    conteneur (« TSK:/etc/passwd », « GZIP:/var/log/x ») : on le retire, sans
    quoi aucun chemin ne correspondrait jamais à ceux des autres faits."""
    for cle in ("filename", "pathspec_location", "display_name"):
        v = e.get(cle)
        if isinstance(v, str) and v:
            if cle == "display_name" and ":" in v[:12]:
                v = v.split(":", 1)[1]
            return v
    return ""


SESSION_MAX_PLASO = timedelta(hours=16)


def _fenetres_session():
    """[(début, fin, acteur, id du fait)] — les sessions déjà établies.

    C'est le recoupement que le rapport demande partout : « une session et ce
    qui s'est passé pendant sa fenêtre ». Les faits portent l'ouverture, et la
    fermeture quand la pièce la donne ; sans elle, on borne, et le fait le dit.
    """
    def iso(d):
        # La MÊME forme que _plaso_horo rend : de l'UTC suffixé Z. Deux
        # horodatages écrits ainsi se comparent comme des chaînes, dans l'ordre
        # du temps — ce qui évite de reconstruire un datetime par événement,
        # et il y en a des millions.
        return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    out = []
    for f in FAITS:
        if f.get("categorie") != "evenement" or "ouverture de session" not in f["fait"]:
            continue
        debut = _horo(f)
        if debut is None or not f.get("acteur"):
            continue
        fin = _horo({"horodatage": f["fin"]}) if f.get("fin") else None
        out.append((iso(debut), iso(fin or debut + SESSION_MAX_PLASO),
                    f["acteur"], f["id"], fin is not None))
    out.sort(key=lambda x: (x[0], x[3]))
    return out


def _comptes_connus():
    """{dossier personnel en minuscules : compte} — pour ranger un chemin."""
    maisons = {}
    for f in FAITS:
        if f.get("categorie") == "compte" and f["fait"].startswith("compte local"):
            maisons[f"/home/{str(f['valeur']).lower()}"] = str(f["valeur"])
    maisons.setdefault("/root", "root")
    return maisons


def plaso(c):
    """La super-timeline, si la collecte en porte une."""
    chemins = trouver_plaso(c)
    if not chemins:
        return
    for chemin in chemins:
        c.lus.add(chemin)
    fichiers, montages = _questions_timeline()
    annonces = {a for demandeurs in fichiers.values()
                for a in (_chemin_annonce(x) for x in demandeurs) if a}
    genres, analyseurs = collections.Counter(), collections.Counter()
    total = illisibles = sans_date = vus = 0
    premier = dernier = None
    trouves, sous_montage, coupes = {}, {}, collections.Counter()
    # Ce que plaso vient RECOUPER avec le reste des faits.
    fenetres = _fenetres_session()
    debuts = [w[0] for w in fenetres]
    maisons = _comptes_connus()
    par_session = collections.Counter()          # id du fait d'ouverture → n
    par_compte = {}                              # compte → [n, premier, dernier]
    jours = set()                                # les journées qui portent une trace
    # Le SCHÉMA réellement lu : les classes dfdatetime rencontrées et les
    # champs du premier événement. C'est ce qui permet de dire, sans rien
    # demander à personne, quelle forme la version installée de plaso produit —
    # et de voir tout de suite si une unité inconnue a été devinée.
    classes, champs = collections.Counter(), None

    for chemin in chemins:
        for ligne in _plaso_lignes(chemin):
            # « -o json » rend un unique tableau : les crochets et la virgule
            # de fin ne sont pas du JSON ligne à ligne, mais le reste l'est.
            ligne = ligne.strip().lstrip("[").rstrip("],")
            if not ligne:
                continue
            total += 1
            try:
                e = json.loads(ligne)
            except json.JSONDecodeError:
                illisibles += 1
                continue
            if not isinstance(e, dict):
                illisibles += 1
                continue
            if champs is None:
                champs = sorted(e)
            dt = e.get("date_time")
            if isinstance(dt, dict):
                classes[str(dt.get("__class_name__") or "?")] += 1
            genres[str(e.get("data_type") or "?")] += 1
            analyseurs[str(e.get("parser") or "?")] += 1
            quand = _plaso_horo(e)
            if quand is None:
                sans_date += 1
            else:
                premier = quand if premier is None or quand < premier else premier
                dernier = quand if dernier is None or quand > dernier else dernier
            if quand is not None:
                jours.add(quand[:10])
            ou = _plaso_chemin(e)
            if ou and maisons:
                # Le dossier personnel range l'événement sous un COMPTE. C'est
                # une imputation faible — un service peut écrire chez
                # quelqu'un — et le fait le dira ; mais c'est la question que
                # l'on pose en premier d'une super-timeline.
                tete = "/".join(ou.lower().split("/", 3)[:3])
                compte = maisons.get(tete) or (maisons.get("/root")
                                               if ou.startswith("/root/") else None)
                if compte:
                    p = par_compte.setdefault(compte, [0, None, None])
                    p[0] += 1
                    if quand is not None:
                        p[1] = quand if p[1] is None or quand < p[1] else p[1]
                        p[2] = quand if p[2] is None or quand > p[2] else p[2]
            if quand is not None and fenetres:
                # La session qui COUVRE cet instant. bisect sur les débuts
                # triés : les sessions se comptent en dizaines, l'événement en
                # millions, et une recherche linéaire par événement coûterait
                # le produit des deux.
                i = bisect.bisect_right(debuts, quand) - 1
                while i >= 0:
                    d, f_, _acteur, ident, _sure = fenetres[i]
                    if quand <= f_:
                        par_session[ident] += 1
                        break
                    i -= 1
            if not ou:
                continue
            base, vise = ou.rsplit("/", 1)[-1].lower(), False
            if base in fichiers:
                vise = True
                liste = trouves.setdefault(base, [])
                if not any(x[2] == ou for x in liste):
                    coupes[base] += 1
                    if len(liste) < 3:
                        liste.append((quand, e.get("timestamp_desc"), ou))
                    elif ou.lower() in annonces:
                        liste[-1] = (quand, e.get("timestamp_desc"), ou)
            for prefixe, _ in montages:
                if ou.startswith(prefixe + "/"):
                    vise = True
                    sous = sous_montage.setdefault(prefixe, [])
                    coupes[prefixe] += 1
                    if len(sous) < MAX_PAR_SUPPORT:
                        sous.append((quand, e.get("timestamp_desc"), ou))
            if not vise and SENSIBLES.search(ou.lower()):
                vus += 1
                if vus <= PLASO_MAX_SENSIBLES:
                    fait("plaso", "activité sur un chemin sensible", ou,
                         c.rel(chemin), f"événement {e.get('data_type') or '?'} "
                         f"de la super-timeline plaso",
                         horodatage=quand, genre=e.get("timestamp_desc") or None,
                         note=_coupe(str(e.get("message") or ""), 200) or None)

    source = c.rel(chemins[0]) if len(chemins) == 1 else "PLASO/"
    fait("plaso", "événements dans la super-timeline plaso", str(total), source,
         "psort -o json_line, une ligne par événement",
         note=(f"du {premier} au {dernier}" if premier else "aucun événement daté")
              + f" ; {len(genres)} familles d'artefact, {len(analyseurs)} analyseurs"
              + ". plaso ouvre les bases, les journaux et les caches que mactime "
                "ne regarde pas : ce qui manque ailleurs peut se trouver ici")
    # Le recensement par famille : c'est lui qui dit ce que la pièce PEUT
    # répondre. Sans lui, l'analyste ne sait pas quoi lui demander.
    for genre, n in genres.most_common(25):
        fait("plaso", "famille d'artefact dans la super-timeline", genre, source,
             "compte des « data_type » du fichier plaso", occurrences=n,
             note=f"{n} événement(s)")
    if len(genres) > 25:
        fait("limite", "familles d'artefact plaso non listées",
             str(len(genres) - 25), source, "compte des « data_type »",
             note=f"{len(genres)} familles au total, les 25 plus nombreuses sont "
                  "citées. Les autres se lisent par « jq -r .data_type | sort | "
                  "uniq -c » sur le fichier")
    # Le schéma lu, toujours posé : c'est lui qui permet de vérifier une date
    # plutôt que de la croire, et de voir si une classe dfdatetime inconnue a
    # été lue avec l'unité par défaut — donc peut-être à tort.
    inconnues = [k for k in classes if k not in _DFDATETIME and k != "?"]
    fait("plaso", "forme du fichier plaso", ", ".join(sorted(classes)) or "sans date_time",
         source, "champs du premier événement et classes dfdatetime rencontrées",
         note="champs : " + ", ".join(champs or ["aucun"])
              + (f" ; CLASSES INCONNUES lues en secondes, ce qui peut être "
                 f"faux : {', '.join(sorted(inconnues))}" if inconnues else
                 " ; toutes les classes de date sont connues")
              + f". Dates retenues entre {_epoch_iso(PLASO_MIN)[:4]} et "
                f"{_epoch_iso(PLASO_MAX)[:4]} : hors de là, c'est une unité mal "
                "devinée, et la ligne est comptée comme non datée",
         confiance="certaine")
    if illisibles or sans_date:
        fait("limite", "lignes plaso non exploitées", str(illisibles + sans_date),
             source, "lecture ligne à ligne du JSON",
             note=f"{illisibles} ligne(s) illisibles, {sans_date} sans date "
                  "retenue. Le format de « psort -o json_line » varie selon la "
                  "version de plaso : si ce compte est élevé, voyez le fait "
                  "« forme du fichier plaso » ci-dessus, puis une ligne du "
                  "fichier — l'horodatage n'est alors ni « timestamp », ni "
                  "« date_time », ni « datetime »")
    # ── ce que plaso RECOUPE avec le reste ──
    for ident, n in sorted(par_session.items()):
        w = next((x for x in fenetres if x[3] == ident), None)
        if w is None or n == 0:
            continue
        debut, fin, acteur, _id, sure = w
        fait("plaso", "activité pendant une session ouverte", str(n), source,
             f"événements plaso dans la fenêtre de la session {ident}",
             horodatage=debut, acteur=acteur, confirme=ident, confiance="forte",
             note=f"{n} événement(s) entre {debut} et {fin}"
                  + ("" if sure else " — la pièce ne donne pas la fermeture : "
                     f"la fenêtre est bornée à {SESSION_MAX_PLASO}, elle n'est "
                     "pas mesurée")
                  + ". Un événement dans la fenêtre d'une session n'est pas "
                    "l'oeuvre de ce compte : un service tourne aussi pendant "
                    "qu'il est connecté. C'est un rapprochement, à confirmer "
                    "sur la pièce")
    for compte, (n, prem, dern) in sorted(par_compte.items()):
        fait("plaso", "activité dans le dossier personnel d'un compte", str(n),
             source, "chemins sous le dossier personnel, dans la super-timeline",
             horodatage=dern, acteur=compte, confiance="forte",
             note=(f"{n} événement(s), du {prem} au {dern}" if prem else
                   f"{n} événement(s), aucun daté")
                  + ". Un chemin sous le dossier d'un compte n'est pas un acte "
                    "de ce compte : un service y écrit aussi. C'est un "
                    "rapprochement, pas une imputation")
    # Les trous : la synthèse des périodes ne voit que les faits que les autres
    # phases ont posés. plaso en porte des millions et peut donc CONTREDIRE un
    # « rien entre le X et le Y » — ou le confirmer, ce qui vaut bien davantage.
    if len(jours) > 1:
        suite = sorted(jours)
        trous = []
        for a_, b_ in zip(suite, suite[1:]):
            da = datetime.strptime(a_, "%Y-%m-%d")
            db = datetime.strptime(b_, "%Y-%m-%d")
            if (db - da).days > PLASO_TROU_JOURS:
                trous.append((a_, b_, (db - da).days))
        fait("plaso", "journées portant une trace dans la super-timeline",
             str(len(jours)), source, "dates distinctes des événements plaso",
             note=f"du {suite[0]} au {suite[-1]}"
                  + (f" ; {len(trous)} intervalle(s) de plus de "
                     f"{PLASO_TROU_JOURS} jours sans aucun événement"
                     if trous else " ; aucun intervalle de plus de "
                     f"{PLASO_TROU_JOURS} jours sans événement"))
        for a_, b_, n in trous[:PLASO_MAX_TROUS]:
            fait("plaso", "aucune trace plaso pendant un intervalle", f"{a_} → {b_}",
                 source, "dates distinctes des événements plaso",
                 horodatage=a_ + "T00:00:00Z", confiance="certaine",
                 note=f"{n} jours sans un seul événement. plaso lit les bases, "
                      "les journaux et les caches : un intervalle vide ICI pèse "
                      "plus lourd qu'un intervalle vide dans la seule timeline "
                      "du système de fichiers. Cela ne dit toujours pas que le "
                      "poste n'a pas servi")
        if len(trous) > PLASO_MAX_TROUS:
            fait("limite", "intervalles plaso non listés",
                 str(len(trous) - PLASO_MAX_TROUS), source,
                 "dates distinctes des événements plaso",
                 note=f"{len(trous)} intervalles au total, "
                      f"{PLASO_MAX_TROUS} cités")

    if vus > PLASO_MAX_SENSIBLES:
        fait("limite", "chemins sensibles plaso : le plafond est atteint",
             str(vus), source, "chemins d'intérêt dans la super-timeline",
             note=f"{vus} événements correspondent, {PLASO_MAX_SENSIBLES} sont "
                  "cités. Les suivants ne sont PAS dans l'analyse")

    # Les questions déjà posées par les autres faits, répondues sur plaso —
    # avec la même exigence que sur mactime : le NOM ne fait pas le fichier.
    for base, demandeurs in sorted(fichiers.items()):
        if base not in trouves:
            continue
        for f in demandeurs:
            annonce = _chemin_annonce(f)
            for quand, genre, ou in trouves[base]:
                meme = annonce is not None and ou.lower() == annonce
                fait("plaso", "fichier retrouvé dans la super-timeline" if meme
                     else "fichier de MÊME NOM dans la super-timeline",
                     ou, source,
                     ("chemin" if meme else "nom") +
                     f" du fichier de {f['id']} cherché dans la super-timeline",
                     horodatage=quand, acteur=f.get("acteur") if meme else None,
                     confiance="certaine" if meme else "à vérifier",
                     confirme=f["id"], genre=genre or None,
                     note=(f"{genre or 'date'} — au chemin annoncé par {f['id']}"
                           if meme else
                           f"MÊME NOM que le fichier de {f['id']}"
                           + (f", mais pas le même chemin : « {annonce} »"
                              if annonce else "")
                           + ". À confirmer avant d'attribuer celui-ci à qui que "
                             "ce soit")
                          + (f" ; {coupes[base]} emplacements portent ce nom"
                             if coupes[base] > 1 else ""))
    for prefixe, entrees in sorted(sous_montage.items()):
        f = next((x for p, x in montages if p == prefixe), None)
        for quand, genre, ou in entrees:
            fait("plaso", "fichier vu sous un support amovible", ou, source,
                 f"chemins sous « {prefixe}/ » dans la super-timeline",
                 horodatage=quand, acteur=f.get("acteur") if f else None,
                 confirme=f["id"] if f else None, genre=genre or None,
                 note=f"{genre or 'date'} — plaso date l'événement ; ce que le "
                      "fichier FAISAIT là demande la pièce elle-même")
        if coupes[prefixe] > MAX_PAR_SUPPORT:
            fait("limite", "support amovible plaso : le plafond est atteint",
                 prefixe, source, f"chemins sous « {prefixe}/ »",
                 note=f"{coupes[prefixe]} événements sous ce point de montage, "
                      f"{MAX_PAR_SUPPORT} cités")


# ── 9 · les synthèses ─────────────────────────────────────────────────
# Celles-ci ne lisent aucune pièce : elles relisent les FAITS déjà établis.
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


# L'hôte d'une URL, l'adresse MAC, l'IPv4. Les bornes de RE_MAC écartent ce qui
# est NOYÉ dans une suite hexadécimale plus longue : une empreinte SSH
# « SHA256:aa:bb:… », une IPv6, une clé écrite en hexadécimal. Sans elles,
# n'importe quelle empreinte rendrait six adresses MAC.
RE_URL_HOTE = re.compile(r'\b(?:https?|ftp)://(?:[^\s/@:]{1,64}(?::[^\s/@]{0,64})?@)?'
                         r'([A-Za-z0-9._-]{1,253})')
RE_MAC = re.compile(r'(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z:])')

# Les champs d'un fait où une adresse est une DONNÉE. « note » n'y est pas :
# elle explique, et ses exemples — « 203.0.113.42 jamais vue ici » —
# deviendraient des adresses trouvées sur le poste.
#
# Aucun des deux n'est marqué « fenêtre » : c'est la VALEUR qui porte sa
# coupure, par le « … » que pose _coupe(). Une table de champs disait que
# « valeur » n'est jamais tronquée — ce qui est faux, neuf sites la coupent —
# et un dixième site l'aurait été sans que rien ne le signale.
CHAMPS_ADRESSE = ("valeur", "contexte")
ADRESSES_MAX = 80

# D'où vient une adresse, en français. C'est TOUT l'intérêt de la synthèse :
# la même IP dans un profil réseau, dans une ligne de journal et dans les
# octets bruts du disque ne raconte pas la même chose.
OU_ADRESSE = {
    "reseau": "configuration réseau", "machine": "configuration système",
    "navigation": "navigation", "telechargement": "téléchargement",
    "chaines": "chaînes du disque", "evenement": "journal",
    "document": "fichier rendu sans nom",
    # « fenêtre » et non « octets bruts » : l'adresse était dans les soixante
    # octets qui entourent un AUTRE motif repéré. Elle est bien là, mais c'est
    # un voisinage, pas une trouvaille — le dire évite de le lire pour plus.
    # Mais un motif peut aussi se reconnaître au NOM du fichier ou à son
    # empreinte : ces faits-là n'ont pas de fenêtre, et parler de fenêtre pour
    # eux serait dire une chose fausse. _ou_adresse tranche sur le fait.
    "interet": "fenêtre d'un motif repéré", "indicateur": "fenêtre d'un motif repéré",
    "persistance": "persistance", "usage": "usage", "suspect": "point d'attention",
}
RANG_CONFIANCE = ("à vérifier", "forte", "certaine")


def _ou_adresse(f):
    """D'où sort une adresse, en français, pour la colonne « vue dans »."""
    ou = OU_ADRESSE.get(f["categorie"], f["categorie"])
    if "fenêtre" in ou and not f.get("contexte"):
        # motif reconnu au nom du fichier ou à son empreinte : pas de fenêtre
        return "motif repéré sur la pièce"
    return ou


def _portee_ip(v):
    """La portée d'une IPv4, ou None si ce n'en est pas une qui désigne une machine.

    RE_IPV4 ne valide pas les octets : « 2024.1.300.5 » lui convient, et un
    disque est plein de numéros de version. On vérifie donc ici, et on écarte
    du même geste ce qui ne désigne personne — bouclage, adresse nulle,
    diffusion. Rendre None pour refuser, comme _portee_mac : un seul contrat
    pour les deux, sinon leurs appelants ne se ressemblent pas.

    Le reste décide de la lecture : une adresse privée est le réseau local et
    ne prouve rien seule, une publique est un contact vers l'extérieur.
    """
    parties = v.split(".")
    if len(parties) != 4 or any(not p.isdigit() or int(p) > 255 for p in parties):
        return None
    a, b = int(parties[0]), int(parties[1])
    if a == 127 or v in ("0.0.0.0", "255.255.255.255"):
        return None
    # Un disque est plein de MASQUES DE SOUS-RÉSEAU — « 255.255.255.0 » est
    # dans chaque fichier de configuration réseau, et il passait tous les
    # contrôles : quatre octets valides, hors des plages privées, hors
    # multidiffusion. La synthèse le rangeait donc en « publique », c'est-à-dire
    # « un contact vers l'extérieur ». Tout masque de /8 ou plus long commence
    # par 255, et 240.0.0.0/4 est de toute façon réservé : le même test écarte
    # les deux. 0.x, c'est « ce réseau-ci » : personne non plus.
    if a == 0 or a >= 240:
        return None
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return "privée"
    if a == 100 and 64 <= b <= 127:
        # 100.64.0.0/10, l'espace partagé des opérateurs : ni privée au sens du
        # réseau local, ni joignable depuis l'extérieur.
        return "partagée (report d'adresse d'opérateur)"
    if a == 169 and b == 254:
        return "auto-attribuée (aucun DHCP n'a répondu)"
    if 224 <= a <= 239:
        return "multidiffusion"
    return "publique"


def _portee_mac(v):
    """Le bit « administrée localement » du premier octet.

    Une adresse MAC qui le porte n'a pas été attribuée par un constructeur :
    c'est une adresse tirée au hasard. Les téléphones et les portables le font
    par défaut pour le Wi-Fi, ce qui est banal — mais cela veut dire que la
    même machine porte une adresse différente à chaque réseau, et qu'on ne peut
    PAS la suivre par là.
    """
    if v.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return ("administrée localement (tirée au hasard)"
            if int(v[:2], 16) & 0b10 else f"constructeur {v[:8].upper()}")


def _hote_url(m):
    """L'hôte d'une URL reconnue, ou None si ce n'en est pas un utilisable."""
    hote = m.group(1).rstrip(".").lower()
    return None if not hote or hote in ("localhost", "127.0.0.1") else hote


# (genre, motif, valeur tirée de la correspondance, portée — None pour refuser).
# Une seule boucle les parcourt : trois boucles jumelles auraient voulu dire
# qu'un quatrième genre — IPv6, hôte d'un en-tête Host: — se recopie une
# quatrième fois, et que la garde de troncature s'oublie à la recopie. C'est
# justement celle que la docstring ci-dessous dit être la plus importante.
GENRES_ADRESSE = (
    ("MAC", RE_MAC, lambda m: m.group(0).lower(), _portee_mac),
    ("IP", RE_IPV4, lambda m: m.group(0), _portee_ip),
    ("URL", RE_URL_HOTE, _hote_url, lambda v: "hôte web"),
)


def _adresses_du_fait(f):
    """(genre, valeur, portée) de chaque adresse écrite dans un fait.

    Une adresse COLLÉE À UNE COUPURE est écartée. Une valeur tronquée porte un
    « … » à l'endroit du couteau — posé par _coupe(), et par la fenêtre de
    soixante octets qui entoure un motif repéré. Sans cette garde,
    « …/torrent/999 https://www.yggtor… » rend un hôte qui n'existe pas, et
    « 192.168.0.55 » coupé d'un octet rend « 192.168.0.5 », qui est une AUTRE
    machine. Inventer une adresse est plus grave que d'en manquer une — celle-là
    figure de toute façon en entier dans la pièce d'où la valeur est tirée.
    """
    for champ in CHAMPS_ADRESSE:
        texte = f.get(champ)
        if not isinstance(texte, str):
            continue
        for genre, motif, valeur_de, portee_de in GENRES_ADRESSE:
            for m in motif.finditer(texte):
                if _touche_une_coupure(m, texte):
                    continue
                valeur = valeur_de(m)
                portee = portee_de(valeur) if valeur else None
                if portee:
                    yield genre, valeur, portee


def _touche_une_coupure(m, texte):
    """Vrai si la correspondance colle au « … » d'une valeur tronquée.

    Sans copier : « texte[:m.start()] » et « texte[m.end():] » taillaient deux
    tranches neuves à CHAQUE correspondance. Sur les valeurs d'aujourd'hui —
    _coupe borne à 120-200 caractères — ça ne se mesure pas ; sur une valeur
    longue et dense en adresses, le produit correspondances × longueur monte
    vite : mesuré 30,5 ms contre 1,8 ms pour 11 000 correspondances dans
    100 000 caractères, soit dix-sept fois. La forme ci-dessous ne coûte rien
    à écrire et supprime la classe entière.
    """
    d = m.start()
    return (d > 0 and texte[d - 1] == "…") or texte.startswith("…", m.end())


def adresses(c):
    """Les adresses réseau vues dans la collecte, chacune avec sa provenance.

    Une adresse ne dit presque rien toute seule ; ce qui compte est OÙ elle a
    été vue. La même IP dans un profil NetworkManager, dans une ligne de
    journal et dans les octets bruts du disque ne raconte pas la même chose :
    la première est une configuration, la deuxième une connexion datée, la
    troisième une trace sans date ni auteur. Chaque ligne porte donc ses
    pièces, ses identifiants de faits, et une confiance qui suit la provenance
    la plus solide — jamais mieux qu'« à vérifier » quand l'adresse ne vient
    que des octets bruts.

    Les URL sont regroupées par HÔTE. Une synthèse qui listerait dix mille
    adresses de pages n'en serait plus une ; le compte des URL distinctes
    reste, et les faits « navigation » gardent le détail.
    """
    # (genre, valeur) → les faits qui la portent, et rien d'autre : pièces,
    # provenances et dates s'en tirent en une ligne à l'émission. Les tenir en
    # plus dans l'accumulateur, c'était écrire DEUX FOIS la règle qui dit
    # qu'une pièce a une provenance — une fois ici, une fois vingt lignes plus
    # bas —, et rien n'obligeait les deux à rester d'accord.
    vues = {}
    for f in FAITS:
        # Ne pas se relire soi-même ; et surtout, ne JAMAIS lire un fait qui
        # affirme une absence : la valeur qu'il porte est celle qu'on a cherchée
        # sans la trouver. La ranger ici reviendrait à dire au lecteur qu'une
        # adresse a été vue sur le poste parce qu'il l'a demandée.
        if f["categorie"] == "adresse" or f.get("trouve") is False:
            continue
        for genre, valeur, portee in _adresses_du_fait(f):
            vues.setdefault((genre, valeur), (portee, []))[1].append(f)
    if not vues:
        return
    # Le plus vu d'abord : sur un disque, c'est l'ordre qui met en tête ce qui
    # a servi, et non ce qui commence par un chiffre bas.
    ordre = sorted(vues.items(), key=lambda kv: (kv[0][0], -len(kv[1][1]), kv[0][1]))
    for (genre, valeur), (portee, faits) in ordre[:ADRESSES_MAX]:
        sources = sorted({f["source"] for f in faits})
        ou = sorted({_ou_adresse(f) for f in faits})
        # Une adresse qui ne vient QUE de pièces sans provenance n'a pas de
        # meilleure confiance qu'« à vérifier », et le rang ne monte que sur
        # les pièces qui, elles, disent d'où elles sortent. Un seul endroit où
        # la règle est écrite, et les dates en découlent.
        datables = [f for f in faits if not f.get("provenance")]
        confiance = max((f.get("confiance", "à vérifier") for f in datables),
                        key=RANG_CONFIANCE.index, default="à vérifier")
        dates = sorted(((h, f) for f in datables for h in (_horo(f),) if h),
                       key=lambda x: (x[0], x[1]["id"]))
        premiere = dates[0][1].get("horodatage") if dates else None
        derniere = dates[-1][1].get("horodatage") if dates else None
        reserve = ("" if datables else
                   " ; vue UNIQUEMENT dans des pièces sans provenance — octets "
                   "bruts du disque, fichier rendu sans nom : ni fichier "
                   "d'origine, ni compte") or ""
        if datables and not dates:
            reserve = (" ; AUCUNE pièce datée ne la porte — on sait qu'elle a "
                       "été écrite sur ce poste, pas quand")
        note = (f"vue dans {len(faits)} fait(s) "
                f"({', '.join(f['id'] for f in faits[:8])}) et "
                f"{len(sources)} pièce(s) ; relevée dans : " + ", ".join(ou) + reserve)
        fait("adresse", f"adresse {genre} vue dans la collecte", valeur,
             sources[0],
             f"toutes les adresses {genre} relevées dans les faits déjà établis",
             horodatage=premiere, confiance=confiance, genre=genre, portee=portee,
             occurrences=len(faits), pieces=len(sources), ou=" / ".join(ou),
             premiere=premiere, derniere=derniere, note=note)
    if len(ordre) > ADRESSES_MAX:
        fait("limite", "synthèse des adresses réseau : seules les plus vues",
             str(ADRESSES_MAX), c.prefix,
             f"les {ADRESSES_MAX} adresses les plus souvent vues, par genre",
             note=f"{len(ordre)} adresses distinctes au total ; les faits « reseau », "
                  "« navigation » et « chaines » les portent toutes. Pour une "
                  "adresse précise, cherchez-la avec --textes")

RE_VIDPID = re.compile(r'idVendor=(?P<vid>[0-9a-fA-F]{4}).*?idProduct=(?P<pid>[0-9a-fA-F]{4})')


def supports(c):
    """Un support amovible par ligne, au lieu d'événements épars.

    Le journal écrit le branchement, le numéro de série et le montage sur des
    lignes séparées, à quelques secondes d'écart. Les recoller donne ce qu'un
    lecteur cherche vraiment : quel support, reconnu à quoi, vu quand pour la
    première et la dernière fois, monté où et par qui.

    Le rapprochement se fait sur le TEMPS, parce que c'est ce que le journal
    donne — le numéro de série suit son branchement de moins d'une minute. Un
    numéro rattaché de cette façon est donc « forte », pas « certaine », et la
    note donne les identifiants des lignes rapprochées pour qu'on vérifie.
    """
    # Un seul parcours des faits, et un seul appel à _horo par fait : la
    # timeline en pose des centaines de milliers, et les relire trois fois puis
    # reconvertir leur date à chaque comparaison coûtait des secondes pleines.
    branchements, series, montages = [], [], []
    par_role = {"usb-branchement": branchements, "usb-serie": series,
                "montage-amovible": montages}
    for f in FAITS:
        cible = par_role.get(f.get("role"))
        if cible is not None:
            cible.append((_horo(f), f))
    if not branchements:
        return
    appareils = {}
    for h, f in branchements:
        m = RE_VIDPID.search(f["valeur"] or "")
        cle = (m.group("vid").lower(), m.group("pid").lower()) if m else ("?", "?")
        a = appareils.setdefault(cle, {"vues": [], "series": {}, "montages": {}})
        a["vues"].append((h, f))
        if h is None:
            continue
        # même seconde ou presque : le journal écrit les deux lignes d'affilée
        for hg, g in series:
            if hg and abs((hg - h).total_seconds()) <= 60:
                a["series"].setdefault(g["valeur"], g["id"])
        for hg, g in montages:
            if hg and 0 <= (hg - h).total_seconds() <= 300:
                a["montages"].setdefault(g["valeur"], (g["id"], g.get("acteur")))
    for (vid, pid), a in sorted(appareils.items()):
        vues = [f for _, f in sorted(a["vues"], key=lambda x: x[0] or datetime.min)]
        ids = ", ".join(f["id"] for f in vues[:8])
        comptes = sorted({c_ for _, c_ in a["montages"].values() if c_})
        # Les identifiants des lignes rapprochées : c'est par eux qu'on refait
        # à la main le rapprochement par le temps, qui n'est qu'« forte ».
        rattaches = ", ".join(sorted({i for i in a["series"].values()}
                                     | {i for i, _ in a["montages"].values()}))
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
                  + (f" ; rapproché par le temps de {rattaches}" if rattaches else "")
                  + (f" ; monté par {', '.join(comptes)}" if comptes else
                     " ; aucun montage relevé — branché sans être monté, ou montage "
                     "hors des journaux collectés")
                  + ("" if a["series"] else " ; AUCUN numéro de série dans le journal : "
                     "deux supports du même modèle ne se distinguent pas"))


# ── mise en ordre ─────────────────────────────────────────────────────
def _zstd(fh):
    """Un lecteur zstd posé sur un flux, ou None si le poste ne sait pas le lire.

    zstd n'entre dans la bibliothèque standard qu'avec Python 3.14 ; avant, il
    faut le paquet « zstandard », qui n'est pas toujours installé. Rendre None
    plutôt que lever laisse l'appelant en faire un fait : un journal qu'on n'a
    pas su ouvrir doit se dire, jamais passer pour un journal vide.
    """
    try:
        from compression import zstd                    # Python 3.14+
        return zstd.ZstdFile(fh)
    except ImportError:
        pass
    try:
        import zstandard                                # si le paquet est là
        return zstandard.ZstdDecompressor().stream_reader(fh)
    except ImportError:
        return None


def _borne(fh, nom):
    """Les octets d'un flux comprimé, jusqu'au plafond d'archive.

    Le plafond vaut pour les cinq compresseurs : un .gz de 64 Ko rendant
    64 Mio faisait un pic mesuré de 141 Mio, et un journal tourné se comprime
    d'un facteur trois cents.
    """
    with contextlib.closing(fh):
        clair = fh.read(PLAFOND_ARCHIVE)
        # Un octet de plus, juste pour savoir s'il en reste. Lire
        # PLAFOND_ARCHIVE + 1 puis trancher DOUBLAIT la mémoire à l'instant
        # précis où le plafond mord — 128 Mio de pic pour un plafond de 64 —,
        # c'est-à-dire là où la borne existe justement pour l'empêcher.
        deborde = bool(fh.read(1))
    if deborde:
        fait("limite", "journal tourné lu en partie", nom, nom,
             f"décompression bornée à {_taille(PLAFOND_ARCHIVE)}",
             note="ce qui suit le plafond n'est PAS dans l'analyse")
    return clair


def decomprimer(nom, blob):
    """Le contenu d'un journal tourné, quel que soit son compresseur.

    logrotate emploie gzip par défaut, mais xz et bzip2 se rencontrent, et
    zstd sur les distributions récentes. Rend None si on ne sait pas ouvrir :
    l'appelant en fait un fait, pour que le silence ne passe pas pour une
    absence de preuve.
    """
    # UNE table de compresseurs, celle de _FLUX, et pas une seconde en if/elif.
    # Le commentaire de _FLUX promet qu'« ajouter un compresseur ici le rend
    # lisible partout » : cette fonction-ci était l'endroit où ce n'était pas
    # vrai. Elle avait sa propre liste, et surtout le plafond n'y couvrait que
    # le .gz — .xz, .lzma et .bz2 passaient par lzma.decompress/bz2.decompress
    # d'un seul bloc, sans aucune borne. Or un .xz comprime BIEN mieux qu'un
    # gzip : la bombe de décompression qu'on croyait désamorcée restait entière
    # sur le compresseur le plus dangereux des quatre.
    bas = nom.lower()
    for suffixe, lecteur in _FLUX:
        if not bas.endswith(suffixe):
            continue
        try:
            fh = lecteur(io.BytesIO(blob))
            return _borne(fh, nom) if fh is not None else None
        except (OSError, EOFError, lzma.LZMAError, ValueError, zlib.error):
            # zlib.error n'hérite d'AUCUNE des quatre autres, et c'est pourtant
            # l'exception normale d'un .gz dont l'en-tête est valide et le corps
            # deflate abîmé — la corruption la plus courante. Elle remontait
            # jusqu'à etape(), qui arrêtait la phase journaux ENTIÈRE : mesuré,
            # 1 fait au lieu de 52, la connexion SSH du membre SUIVANT
            # l'archive abîmée n'étant jamais lue.
            return None
    return blob


# « apt remove », « dnf erase », « pacman -R », « Remove: paquet:amd64 ». Copie
# conforme du motif de conformite-linux/scripts/controles.py : sans lui,
# « apt autoremove teamviewer » était un RETRAIT pour l'un des deux skills et
# rien du tout pour l'autre — « \bremove\b » ne mord pas dans « autoremove ».
RE_RETRAIT = re.compile(r'(?:\b(?:remove|purge|erase|uninstall|autoremove|Erased'
                        r'|Removed)\b|\bpacman\b[^\n]*\s-[A-Za-z]*R)', re.I)


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
    # Facultative, mais c'est la pièce la plus riche quand elle est là : son
    # absence doit se lire comme un choix de collecte, pas comme un oubli.
    ("PLASO", ".jsonl", "la super-timeline plaso",
     "le périphérique, ou le montage",
     "log2timeline puis psort -o json_line", None),
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
# Le quatrième champ est le CRIBLE : les littéraux qu'une correspondance de ce
# motif porte FORCÉMENT. Un groupe = un endroit obligatoire du motif, et les
# chaînes d'un groupe en sont les formes possibles ; il faut donc au moins une
# chaîne de CHAQUE groupe pour qu'une correspondance soit encore possible.
# C'est une condition NÉCESSAIRE, jamais suffisante : le motif est ensuite
# passé tel quel, et lui seul décide. Ce qui est cherché ne change pas ; ce qui
# change est qu'on ne balaie plus deux gigaoctets d'octets pour un « AKIA » qui
# n'y est pas — bytes.find balaie le tampon à la vitesse de la mémoire, là où
# re le parcourt caractère par caractère.
INTERETS = [
    ("clé privée", r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY',
     "une clé privée en clair ; comparez-la aux clés des comptes",
     ((b"-----begin",), (b"private key",)), None),
    ("mot de passe en clair", r'(?:password|passwd|mot_?de_?passe)["\s]{0,3}[=:]["\s]{0,3}[^\s"\',;]{6,64}',
     "un mot de passe écrit en clair dans un fichier ou dans l'espace libre",
     ((b"passw", b"passe"),), r'(?:password|passwd|mot_?de_?passe)["\s]{0,3}[=:]'),
    ("identifiants dans une URL", r'\b[a-z][a-z0-9+.-]{1,10}://[^\s:/@]{1,64}:[^\s@/]{3,64}@[^\s/]{3,}',
     "un identifiant et un secret passés dans une adresse",
     ((b"://",), (b"@",)), r'://[^\s:/@]{1,64}:[^\s@/]{3,64}@'),
    ("chaîne de connexion", r'\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ldaps?)://[^\s]{4,}',
     "une base de données ou un annuaire joint depuis ce poste",
     ((b"mysql", b"postgres", b"mongodb", b"redis", b"amqp", b"ldap"), (b"://",)), None),
    ("jeton AWS", r'\bAKIA[0-9A-Z]{16}\b', "une clé d'accès Amazon", ((b"akia",),), None),
    ("jeton GitHub", r'\bgh[pousr]_[A-Za-z0-9]{36}\b', "un jeton GitHub",
     ((b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"),), None),
    ("jeton Slack", r'\bxox[baprs]-[A-Za-z0-9-]{10,}', "un jeton Slack",
     ((b"xoxa-", b"xoxb-", b"xoxp-", b"xoxr-", b"xoxs-"),), None),
    ("clé Google", r'\bAIza[0-9A-Za-z_-]{35}\b', "une clé d'API Google", ((b"aiza",),), None),
    ("adresse en .onion", r'\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b',
     "un service accessible seulement par Tor", ((b".onion",),), None),
    ("clé de réseau sans fil", r'\bpsk["\s]{0,3}=["\s]{0,3}[^\s"\',;]{8,63}',
     "la clé d'un réseau sans fil, en clair", ((b"psk",),),
     r'psk["\s]{0,3}='),
    ("couple identifiant/mot de passe",
     r'\b[\w.+-]{3,64}@[\w.-]{3,}\.[a-z]{2,12}:[^\s:]{4,64}\b',
     "la forme des listes de comptes qui circulent après une fuite",
     ((b"@",), (b":",)), r'@[\w.-]{3,}\.[a-z]{2,12}:'),
]


def interets():
    """Les motifs de l'outil, à la forme que le moteur d'indicateurs attend.

    Même liste, même moteur, même chercheur que --indicateurs : il n'y a qu'une
    façon de parcourir la collecte, et elle sert aux deux. « absent » à False
    parce qu'un motif de cette liste qu'on ne trouve pas n'est pas un fait —
    ne pas avoir de clé privée qui traîne est la normale, pas une découverte.
    """
    return [{"genre": nom, "valeur": nom, "motif": re.compile(m.encode("utf-8"), re.I),
             "etiquette": quoi, "categorie": "interet", "absent": False,
             "crible": crible,
             "garde": re.compile(garde.encode("utf-8"), re.I) if garde else None}
            for nom, m, quoi, crible, garde in INTERETS]


def lire_textes(chemins):
    """Des chaînes à chercher, une par ligne, sans aucune syntaxe.

    Le fichier d'indicateurs demande « type: valeur » et refuse le reste : très
    bien pour mêler empreintes, adresses et expressions, mais lourd quand on
    n'a qu'une liste — des noms, des références de dossier, des mots-clés
    d'affaire. Ici, une ligne est une chaîne, et c'est tout. Les lignes vides
    et celles qui commencent par « # » sont ignorées ; un « # » en fin de
    ligne sert d'étiquette, comme dans le fichier d'indicateurs — c'est la même
    lecture de ligne, et les chaînes sont cherchées à la lettre.
    """
    liste = []
    for chemin in chemins:
        vus = 0
        with open(chemin, encoding="utf-8") as fh:
            for ligne in fh:
                nue, etiquette = _ligne_liste(ligne)
                if not nue:
                    continue
                liste.append(_a_la_lettre("texte", nue, etiquette))
                vus += 1
        if not vus:
            sys.exit(f"{chemin} : aucune chaîne lisible")
    return liste


def _ligne_liste(ligne):
    """(la chaîne, son étiquette) d'une ligne de liste, ou (None, None).

    La même règle pour les deux formats de liste : ligne vide ou commençant par
    « # » ignorée, « # » en fin de ligne = étiquette. Les séparer laissait les
    deux fichiers diverger sur un détail que l'analyste croit commun.
    """
    nue = ligne.strip()
    if not nue or nue.startswith("#"):
        return None, None
    coupe = re.search(r'\s+#\s*(.*)$', nue)
    if not coupe:
        return nue, None
    return nue[:coupe.start()].strip() or None, coupe.group(1).strip() or None


def _a_la_lettre(genre, valeur, etiquette):
    """Un indicateur cherché À LA LETTRE, sans tenir compte de la casse.

    Jamais comme une expression rationnelle : quelqu'un qui écrit
    « Dupont (RH) » veut ces caractères-là, pas un groupe de capture.
    """
    return {"genre": genre, "valeur": valeur, "etiquette": etiquette,
            "motif": re.compile(re.escape(valeur.encode("utf-8")), re.I),
            # une chaîne cherchée à la lettre est à elle seule son crible :
            # le motif ne peut correspondre nulle part où elle n'est pas
            "crible": ((valeur.encode("utf-8").lower(),),)}


def lire_indicateurs(chemin):
    liste = []
    with open(chemin, encoding="utf-8") as fh:
        for num, ligne in enumerate(fh, 1):
            nue, etiquette = _ligne_liste(ligne)
            if not nue:
                continue
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
                liste.append(_a_la_lettre(genre, valeur, etiquette))
                continue
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


def _membres_zip(ouvrir, etat):
    import zipfile
    rendu = 0
    try:
        with contextlib.closing(ouvrir()) as src, zipfile.ZipFile(src) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if rendu + info.file_size > PLAFOND_ARCHIVE:
                    etat["tronque"] = "plafond d'archive atteint"
                    return
                try:
                    with z.open(info) as fh:
                        # par blocs : un membre de 200 Mo ne devient jamais un
                        # seul bloc d'octets en mémoire
                        for m in iter(lambda: fh.read(1 << 20), b""):
                            yield m
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    continue           # membre chiffré ou abîmé : les autres restent
                rendu += info.file_size
    except (OSError, zipfile.BadZipFile, EOFError, ValueError):
        etat["illisible"] = "archive illisible"


def _flux_pdf(ouvrir, etat, fenetre=1 << 24):
    """Les flux compressés d'un PDF, quand ils le sont en zlib.

    Un PDF n'est pas une archive : c'est un format à objets, dont le texte vit
    dans des flux souvent comprimés en FlateDecode. On ne cherche pas à le
    rendre lisible — extraire un texte de PDF demande une bibliothèque —, on
    veut seulement que les octets DÉCOMPRESSÉS passent sous les motifs. Un
    mot de passe écrit dans un PDF y devient visible ; sa mise en page, non.

    Lu par fenêtres : un PDF hostile de plusieurs centaines de mégaoctets
    tiendrait sinon d'un seul bloc en mémoire, et le rapport n'en tire que
    quelques milliers d'octets. Un flux à cheval sur deux fenêtres se voit
    quand même — on garde ce qui suit la dernière balise fermante.
    """
    rendu, reste = 0, b""
    try:
        with contextlib.closing(ouvrir()) as fh:
            for bloc in iter(lambda: fh.read(fenetre), b""):
                brut, fin = reste + bloc, 0
                for m in RE_FLUX_PDF.finditer(brut):
                    fin = m.end()
                    try:
                        clair = zlib.decompress(m.group(1))
                    except zlib.error:
                        continue       # flux non comprimé, ou autre filtre
                    rendu += len(clair)
                    if rendu > PLAFOND_ARCHIVE:
                        etat["tronque"] = "plafond d'archive atteint"
                        return
                    yield clair
                reste = brut[fin:]
                if len(reste) > fenetre:
                    # un flux plus long qu'une fenêtre : on ne le reconstitue
                    # pas, mais on ne le tait pas non plus
                    etat["tronque"] = "flux PDF plus long qu'une fenêtre de lecture"
                    reste = b""
    except OSError:
        return


def _morceaux(lecteur, ouvrir, etat, bloc=1 << 20):
    """Les blocs décomprimés d'un flux, jusqu'au plafond d'archive."""
    try:
        fh = lecteur(ouvrir())
    except (OSError, EOFError, ValueError, lzma.LZMAError):
        etat["illisible"] = "archive illisible"
        return
    if fh is None:
        etat["illisible"] = "compresseur non pris en charge sur ce poste"
        return
    rendu = 0
    try:
        with contextlib.closing(fh):
            for m in iter(lambda: fh.read(bloc), b""):
                rendu += len(m)
                if rendu > PLAFOND_ARCHIVE:
                    etat["tronque"] = "plafond d'archive atteint"
                    return
                yield m
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error):
        etat["illisible"] = "archive illisible"


# Un couple (suffixe, lecteur de flux). La même table sert au journal tourné
# rangé dans un tar et au fichier comprimé posé sur le disque : ajouter un
# compresseur ici le rend lisible partout, et il n'y a pas d'endroit où un
# .zst serait vu et un autre où il passerait pour du binaire.
# Le .gz y figure comme les autres. _blocs sait l'ouvrir depuis toujours, mais
# _comprimee rendait False et _apercu était donc AVEUGLE au .gz : un document
# rendu par le carving sous ce nom n'était jamais caractérisé, alors que le
# commentaire promettait qu'« ajouter un compresseur ici le rend lisible
# partout ». Le plus courant de tous n'y était pas.
# gzip.GzipFile prend un NOM DE FICHIER en premier argument, là où BZ2File et
# LZMAFile acceptent l'objet : d'où le fileobj= explicite. Sans lui, la phase
# entière tombait sur « TypeError: expected str, bytes or os.PathLike ».
_FLUX = ((".gz", lambda fh: gzip.GzipFile(fileobj=fh)), (".bz2", bz2.BZ2File),
         (".xz", lzma.LZMAFile), (".lzma", lzma.LZMAFile),
         (".zst", lambda fh: _zstd(fh)))


def _decomprime(nom, ouvrir, etat):
    """Le contenu lisible d'une source comprimée, morceau par morceau, ou None.

    None veut dire « cette source est déjà son propre contenu » — et c'est ce
    qui permet à _blocs de n'avoir qu'une forme de sortie pour tout le monde.

    « ouvrir » rend un fichier binaire NEUF à chaque appel : un open() pour une
    pièce posée sur le disque, un BytesIO pour un membre de tar déjà en
    mémoire. La décompression ignore donc la provenance — et un journal tourné
    vaut le même traitement qu'il soit sur le disque ou rangé dans une archive.
    """
    bas = nom.lower()
    if bas.endswith(_ZIP):
        return _membres_zip(ouvrir, etat)
    if bas.endswith(".pdf"):
        return _flux_pdf(ouvrir, etat)
    for suffixe, lecteur in _FLUX:
        if bas.endswith(suffixe):
            return _morceaux(lecteur, ouvrir, etat)
    return None


# Le pas d'entrée du décompresseur. Court, parce que zlib lève pour TOUT
# l'appel : c'est la quantité de contenu sain qu'on accepte de perdre autour
# d'un octet abîmé. Assez long, cependant, pour que la boucle Python reste
# négligeable devant le travail de zlib.
PAS_DEFLATE = 1 << 15


def _blocs(nom, ouvrir, etat=None, bloc=1 << 20):
    """Rend (brut, clair) : les octets de la source, et son contenu lisible.

    Le strings d'un disque pèse des gigaoctets : il ne peut être ni chargé en
    mémoire, ni lu deux fois. Tout passe donc en flux. L'empreinte se calcule
    sur « brut », les motifs courent sur « clair » — pour une source ordinaire
    les deux sont le même bloc, et rien n'est copié.

    Un .gz se décompresse au fil des blocs bruts, ce qui donne les deux en UNE
    lecture. Une archive (zip, docx, pdf, bz2, xz, zst) se lit deux fois : ses
    octets pour l'empreinte, puis son contenu. C'est le prix pour voir dans un
    document rendu par photorec, et il ne se paie que sur ces sources-là — et
    seulement si l'appelant va jusqu'au bout : le second passage n'est ouvert
    qu'une fois le premier épuisé.

    AUCUN bloc « clair » ne dépasse la taille demandée, quelle que soit la
    compression. C'est une garantie, pas un détail : un journal tourné se
    comprime d'un facteur trois cents, et un bloc d'entrée d'un mégaoctet rendu
    d'un seul tenant faisait un tampon de deux cents mégaoctets — que le
    chercheur recopie, puis balaie une fois par motif. L'extraction paraissait
    alors bloquée, et le plafond d'archive, lui, ne jouait jamais sur cette
    voie : la garde contre les bombes de décompression ne couvrait pas la forme
    comprimée la plus courante de toutes.
    """
    etat = {} if etat is None else etat
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS) if nom.lower().endswith(".gz") else None
    comprime = dec is None and _comprimee(nom)
    rendu = 0
    with contextlib.closing(ouvrir()) as fh:
        for brut in iter(lambda: fh.read(bloc), b""):
            if dec is None:
                yield brut, (b"" if comprime else brut)
                continue
            if "tronque" in etat:
                # Plafond atteint : on lit encore, mais seulement pour
                # l'empreinte — qui doit porter sur le fichier ENTIER, sinon
                # une empreinte recherchée ne correspondrait plus à rien.
                yield brut, b""
                continue
            entree, premier = brut, brut
            while entree:
                tranche, reste = entree[:PAS_DEFLATE], entree[PAS_DEFLATE:]
                try:
                    # L'ENTRÉE est découpée, et pas seulement la sortie. zlib
                    # lève pour tout l'appel : si on lui donne le mégaoctet
                    # d'un coup, un octet abîmé à la fin fait perdre le
                    # mégaoctet entier de contenu SAIN qui le précède. Mesuré :
                    # un mot de passe placé avant la corruption ne sortait pas
                    # du tout. Avec un pas court, seule la tranche abîmée est
                    # perdue, et tout ce qui précède a déjà été rendu.
                    clair = dec.decompress(tranche, bloc)
                except zlib.error as e:
                    # L'exception remontait jusqu'à lire_source, qui l'avalait
                    # SANS RIEN NOTER : le fichier disparaissait en entier de
                    # l'analyse — et son EMPREINTE avec lui, alors qu'elle ne
                    # dépend d'aucune décompression. On continue donc à lire
                    # les octets bruts, pour que l'empreinte porte sur le
                    # fichier entier ; mais PAS de second passage, qui relirait
                    # depuis le début et compterait deux fois ce qui précède.
                    etat["illisible"] = f"flux comprimé abîmé ({e})"
                    yield premier, b""
                    dec, comprime = None, False
                    break
                rendu += len(clair)
                # « premier » ne sort qu'une fois : répéter les octets bruts
                # les compterait deux fois dans l'empreinte.
                yield premier, clair
                premier = b""
                if rendu > PLAFOND_ARCHIVE:
                    etat["tronque"] = "plafond d'archive atteint"
                    break
                # Un .gz peut porter PLUSIEURS membres — « cat a.gz b.gz »,
                # « gzip -c f1 f2 », des rotations concaténées. decompressobj
                # s'arrête au premier ; le mot-clé rangé dans le second sortait
                # « ABSENT ». unused_data porte alors ce qui reste à ouvrir.
                # unconsumed_tail et unused_data ne portent que ce qui reste
                # de la TRANCHE : le reste de l'entrée s'y ajoute, il ne s'y
                # substitue pas. L'écrire autrement perdait des octets — 9,6 Mo
                # rendus sur 25, ce que la régression a vu tout de suite.
                if dec.eof:
                    entree = dec.unused_data + reste
                    if entree:
                        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    entree = dec.unconsumed_tail + reste
    if comprime:
        for morceau in _decomprime(nom, ouvrir, etat) or ():
            yield b"", morceau


def _comprimee(nom):
    """Vrai si _decomprime saura tirer un contenu de cette source."""
    bas = nom.lower()
    return bas.endswith(_ZIP) or bas.endswith(".pdf") \
        or any(bas.endswith(s) for s, _ in _FLUX)


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

    def __enter__(self):
        self.fh = open(self.chemin, "w", encoding="utf-8")
        self.fh.write(json.dumps({"signature": self.signature},
                                 ensure_ascii=False) + "\n")
        self.fh.flush()
        return self

    def __exit__(self, *_):
        if self.fh:
            self.fh.close()
            self.fh = None

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

    def reporter(self, entree):
        """Recopie au journal NEUF une entrée du journal précédent.

        Sans elle, une reprise RÉUSSIE se détruit elle-même : __enter__ ouvre
        le journal en écriture, donc le vide, et seuls les fichiers réellement
        relus y sont notés — c'est-à-dire aucun. Le journal retombe à sa
        seule ligne d'en-tête, et la reprise SUIVANTE reparcourt toute la
        collecte. Le premier plantage était couvert ; le second ne l'était
        plus, alors que c'est exactement le cas où l'on reprend deux fois.
        """
        if self.fh:
            self.fh.write(json.dumps(entree, ensure_ascii=False) + "\n")
            self.fh.flush()

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


def _rejouer(f):
    """Repose un fait du journal, avec un identifiant neuf.

    Les identifiants sont séquentiels : rejoués dans le même ordre, ils
    retombent sur les mêmes. C'est ce qui permet à un rapport repris de citer
    les mêmes numéros qu'un rapport d'un seul tenant.
    """
    FAITS.append({"id": f"F{len(FAITS) + 1:04d}", **f})


def indicateurs(c, liste, reprise=None, fichiers=()):
    """Cherche chaque indicateur dans TOUTE la collecte, source par source.

    Une seule lecture par source, quel que soit le nombre de motifs : les
    octets défilent une fois et chaque motif les regarde passer. Les empreintes
    se calculent au fil de l'eau. Et quand seuls des noms sont demandés, rien
    n'est lu.

    « fichiers » sont les listes de recherche elles-mêmes : posées DANS la
    collecte, elles s'y trouveraient, puisque chaque chaîne y figure.
    """
    empreintes = {g: {x["valeur"]: x for x in liste if x["genre"] == g}
                  for g in ("sha256", "sha1", "md5")}
    empreintes = {g: d for g, d in empreintes.items() if d}
    noms = [x for x in liste if x["genre"] == "fichier"]
    motifs = [x for x in liste if x["motif"] is not None]
    cribles = any(x.get("crible") for x in motifs)
    lire = bool(empreintes or motifs)
    soi = {c.rel(os.path.abspath(x)) for x in fichiers}
    par_valeur = {x["valeur"]: x for x in liste}
    nouveaux = []      # les valeurs trouvées, dans l'ordre, pour le journal

    def trouve(x):
        """Note qu'un indicateur vient d'être vu — une fois, à sa découverte."""
        if not x.get("trouve"):
            x["trouve"] = True
            nouveaux.append(x["valeur"])

    def examiner(source, nom, blocs=None, chevauche=1 << 12):
        """Le nom, l'empreinte et les motifs, en UNE lecture.

        « blocs » est une suite de (brut, clair) — un seul couple pour un
        membre d'archive déjà en mémoire, autant que nécessaire pour un gros
        fichier. Tout passe par ici : sans quoi une source qu'on ne peut pas
        charger d'un bloc réclame un second chercheur, et les deux divergent
        — la première victime étant le contrôle des NOMS, qui n'a rien à voir
        avec la taille du fichier.

        Chaque motif est cherché SÉPARÉMENT sur le même tampon, et c'est le
        point important. Une alternative unique ne rend que des correspondances
        qui ne se CHEVAUCHENT PAS : le motif interne « password = ... » avale
        « Bienvenue2025! », et la chaîne que l'analyste a demandée sort
        « ABSENTE » alors qu'elle est là, dans le même fichier. Un faux négatif
        sur une recherche demandée est la pire erreur que ce script puisse
        commettre — on lui fait dire qu'une preuve n'existe pas. Des passes
        séparées ne peuvent pas se voler une correspondance : la question ne se
        pose plus.

        C'est aussi le plus rapide, à rebours de l'intuition : re ne sait pas
        préfiltrer une alternative, dont le coût croît avec le nombre de
        branches. Mesuré sur 8 Mo de texte sans aucune correspondance — 1,0 s
        contre 1,9 s à 11 motifs, 2,7 s contre 22,6 s à 61, 7,9 s contre 174 s
        à 211, soit vingt-deux fois plus dès qu'un fichier --textes s'en mêle.

        Le chevauchement n'est pas un détail : une chaîne à cheval sur deux
        blocs serait invisible sans lui. On garde donc la queue du bloc
        précédent, et on ignore ce qui tombe entièrement dedans, sinon la même
        occurrence serait comptée deux fois.
        """
        base = os.path.basename(nom)
        for x in noms:
            if fnmatch.fnmatch(base, x["valeur"]) or fnmatch.fnmatch(nom, x["valeur"]):
                trouve(x)
                fait(x.get("categorie", "indicateur"), "fichier au nom recherché",
                     nom, source, f"nom comparé au motif « {x['valeur']} »",
                     trouve=True, note=x["etiquette"])
        if blocs is None:
            return
        hs = {g: hashlib.new(g) for g in empreintes}
        comptes_, contextes = {}, {}
        # Les (motif, position absolue de début) déjà comptés. La
        # déduplication ne peut PAS se faire sur la fin de la correspondance :
        # six des onze motifs d'INTERETS ont une queue gourmande à longueur
        # variable — « mot de passe en clair » finit par {6,64} —, et cette fin
        # BOUGE d'un tour à l'autre. Tranchée par la fin du tampon au tour k,
        # la correspondance repartait du chevauchement au tour k+1, s'allongeait
        # dans le bloc neuf, et était RECOMPTÉE. Mesuré : « occurrences: 2 »
        # pour un seul « password=SuperMotDePasse2024 » posé à cheval, et sept
        # pour un unique secret dans un .docx, dont les membres XML donnent des
        # blocs courts. Le début, lui, ne bouge jamais.
        # « vus » porte ce qui a été compté au tour PRÉCÉDENT et peut reparaître
        # à celui-ci ; « neufs » se remplit pour le tour suivant. On n'y inscrit
        # que les correspondances qui commencent dans la queue reprise : les
        # autres ne repasseront jamais. Mesuré : la table reconstruite à chaque
        # tour coûtait plus que l'inscription qu'elle épargnait.
        vus, neufs, depart = set(), set(), 0
        reste = b""
        for brut, clair in blocs:
            for h in hs.values():
                h.update(brut)
            if not clair or not motifs:
                continue
            tampon = reste + clair
            # Le tampon en minuscules, UNE fois pour tous les motifs : le
            # crible de chacun s'y cherche ensuite avec bytes.__contains__,
            # qui balaie la mémoire au lieu de la parcourir. re.I sur des
            # octets ne replie que l'ASCII, et bytes.lower() non plus : les
            # deux voient exactement les mêmes correspondances.
            bas = tampon.lower() if cribles else None
            for i, x in enumerate(motifs):
                crible = x.get("crible")
                if crible and not all(any(lit in bas for lit in groupe)
                                      for groupe in crible):
                    continue        # aucune correspondance possible ici
                # La GARDE : un MORCEAU du motif lui-même, donc encore une
                # condition nécessaire — mais qui commence, elle, par un
                # littéral. re saute alors d'un « @ » au suivant au lieu
                # d'essayer « [\w.+-]{3,64} » à chaque octet du tampon, et
                # elle s'arrête à la première correspondance là où finditer
                # doit toutes les rendre. Là où le crible ne trie plus rien —
                # un disque est plein de « @ » et de « :// » —, elle trie.
                garde = x.get("garde")
                if garde is not None and not garde.search(tampon):
                    continue
                for m in x["motif"].finditer(tampon):
                    debut, fin = m.span()
                    absolu = depart + debut
                    cle = (i, absolu)
                    if cle not in vus:
                        comptes_[i] = comptes_.get(i, 0) + 1
                    if debut >= len(tampon) - chevauche:
                        neufs.add(cle)
                    # Le contexte se REMPLACE quand la même correspondance
                    # reparaît plus longue : celle du tour d'avant était
                    # tranchée par la fin du tampon, et rien ne le disait. Le
                    # rapport montrait alors « password=SuperMotDe » comme un
                    # mot de passe entier — une citation d'une chose qui n'a
                    # jamais existé, exactement le piège que les « … » de
                    # _coupe servent à éviter.
                    # Le contexte du PREMIER motif trouvé, puis remplacé tant
                    # que c'est la même correspondance : le tampon ne grandit
                    # qu'à droite, donc la reparaître, c'est s'être allongée.
                    if contextes.get(i, ("", absolu))[1] == absolu:
                        d, f = max(0, debut - 60), min(len(tampon), fin + 60)
                        # Les « … » disent que la fenêtre a TRANCHÉ, et de quel
                        # côté. Sans eux, une adresse coupée par le couteau se
                        # lit comme une adresse entière — « https://www.yggtor »
                        # devient un hôte qui n'a jamais existé.
                        contextes[i] = (("…" if d else "")
                                        + tampon[d:f].decode("utf-8", "replace")
                                          .replace("\n", " ")
                                        + ("…" if f < len(tampon) else ""),
                                        absolu)
            reste = tampon[-chevauche:]
            depart += len(tampon) - len(reste)
            vus, neufs = neufs, set()
        for g, attendus in empreintes.items():
            h = hs[g].hexdigest()
            if h in attendus:
                trouve(attendus[h])
                fait(attendus[h].get("categorie", "indicateur"),
                     f"fichier à l'empreinte {g} recherchée", nom, source,
                     f"{g} du fichier = {h}", trouve=True,
                     note=attendus[h]["etiquette"])
        for i, n in sorted(comptes_.items()):
            x = motifs[i]
            trouve(x)
            contexte, octet = contextes[i]
            interet = x.get("categorie") == "interet"
            fait(x.get("categorie", "indicateur"),
                 # Le genre est dans la VALEUR ; le répéter dans le libellé le
                 # rendrait redondant et bancal — « clé privée repéré ».
                 "repéré dans les octets d'un fichier" if interet
                 else f"{x['genre']} recherché présent dans un fichier",
                 x["valeur"], source,
                 f"motif « {x['valeur']} » cherché dans les octets du fichier",
                 octet=octet, occurrences=n, contexte=contexte, trouve=True,
                 confiance="à vérifier" if interet else "certaine",
                 note=f"{n} occurrence(s) ; la première vers l'octet {octet}, autour "
                      f"d'elle : « {contexte} »"
                      + (f" — {x['etiquette']}" if x["etiquette"] else "")
                      + (". Trouvé dans les octets : ni daté, ni imputable, et peut "
                         "venir d'un paquet d'installation autant que d'un fichier du "
                         "compte. À confirmer sur la pièce citée" if interet else ""))

    def lire_source(source, nom, ouvrir):
        """Une source soumise aux motifs, et ce qu'on n'a pas su en lire.

        Une seule voie pour tout le monde : _blocs décide seul s'il faut
        décompresser, et rend toujours des blocs. Un .gz — le strings d'un
        disque — n'est donc ni chargé d'un coup, ni cherché dans ses octets
        comprimés, où rien ne pourrait correspondre ; et un journal tourné
        rangé dans un tar est lu comme s'il était posé sur le disque, faute de
        quoi il sortirait « ABSENT » de ses propres lignes.
        """
        etat = {}
        try:
            examiner(source, nom, _blocs(nom, ouvrir, etat))
        except OSError as e:
            # zlib.error n'a plus à être rattrapée ici : _blocs la traite et la
            # note dans etat, ce qui laisse examiner() aller jusqu'au bout et
            # rendre l'empreinte. L'avaler ICI la rendait muette.
            etat.setdefault("illisible", f"{type(e).__name__} à la lecture ({e})")
        # Une archive tronquée ou illisible se DIT : sans ça, un document qu'on
        # n'a pas su ouvrir ressemblerait à un document sans rien dedans, ce
        # qui n'est pas la même chose du tout.
        for cle, quoi in (("tronque", "archive lue en partie"),
                          ("illisible", "archive non lisible")):
            if cle in etat:
                fait("limite", quoi, source, source,
                     "décompression pour y chercher les motifs",
                     note=etat[cle] + f" ; plafond {_taille(PLAFOND_ARCHIVE)}. "
                          "Le contenu non lu n'a été soumis à aucun motif")

    def parcourir(chemin, rel):
        """Ce qu'on lit d'une pièce : un tar membre par membre, sinon la pièce."""
        if chemin.endswith(".tar.gz"):
            for nom, blob in c.membres_tar(chemin, None if lire else lambda n: False):
                if blob is None:
                    examiner(f"{rel} → {nom}", nom)
                else:
                    lire_source(f"{rel} → {nom}", nom, lambda b=blob: io.BytesIO(b))
            if not lire:
                for nom in c.mtimes.get(chemin, {}):
                    examiner(f"{rel} → {nom}", nom)
        elif not lire:
            examiner(rel, rel)
        else:
            c.lus.add(chemin)
            lire_source(rel, rel, lambda: open(chemin, "rb"))

    for d, sous, noms_fichiers in os.walk(c.racine):
        # os.walk n'a pas d'ordre garanti : sans ces deux tris, la reprise
        # rejouerait les faits dans un autre ordre que la première fois, et les
        # identifiants changeraient. Le tri est donc ici une exigence, pas un
        # confort. Trier les sous-dossiers EN PLACE suffit — os.walk relit la
        # liste pour descendre —, et rien n'oblige à énumérer tout l'arbre avant
        # d'ouvrir le premier fichier : une collecte porte des centaines de
        # milliers de fichiers rendus par le carving.
        sous.sort()
        noms_fichiers.sort()
        for f in noms_fichiers:
            chemin, rel = os.path.join(d, f), c.rel(os.path.join(d, f))
            if rel in soi:
                continue
            deja = reprise.reutilisable(rel, chemin) if reprise else None
            if deja is not None:
                for x in deja.get("trouves", ()):
                    if x in par_valeur:
                        par_valeur[x]["trouve"] = True
                for fa in deja["faits"]:
                    _rejouer(fa)
                # le journal se réécrit à chaque passage : ce qui n'y est pas
                # recopié est perdu pour la reprise d'après
                reprise.reporter(deja)
                # La pièce a bien été ANALYSÉE, même si elle ne l'a pas été à
                # ce passage-ci : le manifeste doit la porter. Sans cette
                # ligne, une reprise rendait un manifeste amputé — il listait
                # les seules pièces relues, et prétendait donc que le reste
                # n'avait pas été lu. C'est la preuve « quels octets ont été
                # analysés » qui devenait fausse, en silence.
                c.lus.add(chemin)
                continue
            # Un seul endroit qui note au journal : une pièce lue et non notée
            # serait relue à chaque reprise, et une branche ajoutée plus tard
            # sauterait le journal sans que rien ne le signale.
            debut_faits, debut_trouves = len(FAITS), len(nouveaux)
            parcourir(chemin, rel)
            if reprise:
                reprise.noter(rel, chemin, FAITS[debut_faits:],
                              nouveaux[debut_trouves:])
    for x in liste:
        if x.get("absent") is False:
            continue          # l'absence d'un motif de l'outil n'est pas un fait
        if not x.get("trouve"):
            # « trouve » DIT la polarité, des deux côtés — ici False, et True
            # partout où l'on pose une trouvaille. Sans elle, seule la phrase
            # française distingue « présent » d'« ABSENT », et la valeur d'un
            # fait d'absence — une IP, un domaine — se lit comme n'importe
            # quelle autre : la synthèse des adresses rangeait parmi les
            # adresses VUES sur le poste celles que l'analyste avait justement
            # cherchées SANS les trouver. Marquer la seule branche négative
            # aurait laissé la prochaine passer en silence.
            fait("indicateur", f"{x['genre']} recherché ABSENT de la collecte", x["valeur"],
                 c.prefix, "recherche dans chaque fichier et chaque membre d'archive",
                 trouve=False,
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


def colonnes_csv(faits):
    """Les colonnes de tête, puis tout champ qu'un fait porte en plus.

    Dérivées et non déclarées : le CSV dit alors le MÊME contenu que le .jsonl,
    ce que sa promesse annonce, et un champ ajouté à un fait apparaît sans que
    personne ait à penser à cette liste.
    """
    return COLONNES_CSV + tuple(sorted({k for f in faits for k in f}
                                       - set(COLONNES_CSV)))


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


def provenance(collecte, questions, listes):
    """Ce qui décide des faits : l'outil, la collecte, et les questions posées.

    Une seule valeur pour deux usages qui sont la même question — « quelle
    exécution a produit ces faits ? ». Le journal de reprise s'en sert pour
    refuser un journal établi autrement ; le manifeste la publie, pour qu'un
    lecteur puisse dire par quelle version de l'outil et sur quelles questions
    les faits ont été tirés.

    Les tenir séparés, comme avant, coupait la preuve en deux moitiés qui se
    manquaient l'une l'autre : le journal se rejouait après une modification du
    code, et le manifeste taisait ce qu'on avait cherché.
    """
    moi = os.path.abspath(__file__)
    detail = {
        "extracteur": {"fichier": os.path.basename(moi), "sha256": empreinte(moi)},
        "collecte": os.path.abspath(collecte),
        # Dans l'ORDRE des arguments : les mêmes listes données dans l'autre
        # sens ne posent pas les questions dans le même ordre, donc ne rangent
        # pas les faits sous les mêmes numéros.
        "listes_de_recherche": [{"fichier": x, "sha256": empreinte(x)}
                                for x in listes if os.path.isfile(x)],
        # Le contenu des listes est couvert par leur empreinte, et celui de la
        # liste interne par l'empreinte de l'extracteur : le compte suffit ici.
        "questions": len(questions),
    }
    return detail, hashlib.sha256(
        json.dumps(detail, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def manifeste(c, sortie, argv, prov, signature):
    """Ce qui prouve QUELS octets ont été analysés, par quel outil, et pour
    répondre à quelles questions.

    Le manifeste porte une date : il décrit l'exécution, pas les pièces. Les
    faits, eux, ne dépendent que de la collecte et des questions — deux
    extractions de même provenance rendent le même fichier de faits, à l'octet
    près.
    """
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
        **prov,
        "provenance_sha256": signature,
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
    ap.add_argument("--indicateurs", metavar="FICHIER",
                    help="chaînes, empreintes, adresses à chercher dans toute la "
                         "collecte, une par ligne : voir references/indicateurs.md")
    ap.add_argument("--textes", metavar="FICHIER", action="append", default=[],
                    help="chaînes à chercher, UNE PAR LIGNE et sans syntaxe : des "
                         "noms, des références, des mots-clés. Répétable. Cherchées "
                         "à la lettre, sans tenir compte de la casse")
    ap.add_argument("--sans-reprise", action="store_true",
                    help="ignorer le journal de reprise et reparcourir toute la "
                         "collecte, même ce qui a déjà été lu")
    args = ap.parse_args()

    c = Collecte(args.collecte)

    def etape(nom, fn):
        """Une phase, son compte de faits, et son plantage qui n'emporte rien.

        Une phase qui échoue ne doit pas coûter les quatorze autres : la
        collecte d'en face est une pièce à conviction, souvent incomplète ou
        abîmée, et un rapport partiel vaut mieux qu'une trace de pile.
        """
        avant = len(FAITS)
        try:
            fn(c)
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! {nom} : {type(e).__name__} {e}", file=sys.stderr)
        print(f"  {nom:22s} {len(FAITS) - avant:5d} faits", file=sys.stderr)

    # Les PRODUCTEURS lisent les pièces ; les SYNTHÈSES ne lisent que les faits
    # déjà posés. Les séparer en deux listes rend la règle structurelle au lieu
    # de tenir dans un commentaire : une synthèse rangée par mégarde au milieu
    # des producteurs ne verrait que la moitié de ce qu'elle doit voir, sans
    # erreur ni test qui le dise.
    for nom, fn in (("complétude", completude),
                    ("machine", machine), ("comptes et domaine", comptes),
                    ("sessions", sessions), ("journaux", journaux),
                    ("réseau", reseau), ("navigation", navigation),
                    ("historique des paquets", historique_paquets),
                    ("persistance", persistance), ("supprimés", supprimes),
                    ("chaînes des disques", chaines),
                    ("documents rendus", documents), ("timeline", timeline),
                    ("super-timeline plaso", plaso)):
        etape(nom, fn)
    # Un seul parcours de la collecte pour les deux listes : celle de l'outil,
    # cherchée à chaque fois, et celle de l'analyste quand il en donne une.
    demandes = lire_indicateurs(args.indicateurs) if args.indicateurs else []
    demandes += lire_textes(args.textes)
    tous = interets() + demandes
    listes = ([args.indicateurs] if args.indicateurs else []) + list(args.textes)
    # La provenance couvre l'outil, la collecte ET les questions posées :
    # reprendre un journal établi autrement rendrait des réponses à des
    # questions qu'on ne pose plus, ou tirées d'un code qu'on n'a plus.
    prov, signature = provenance(args.collecte, tous, listes)
    journal = os.path.splitext(args.sortie)[0] + "-reprise.jsonl"
    rep = Reprise(journal, signature)
    if args.sans_reprise:
        with contextlib.suppress(OSError):
            os.unlink(journal)
    elif rep.charger():
        print(f"  reprise : {len(rep.connus)} fichiers déjà parcourus, relus depuis "
              f"{os.path.basename(journal)}", file=sys.stderr)
    # etape() et non un compte à la main : c'est la phase la PLUS LONGUE et la
    # plus exposée — elle ouvre chaque archive de la collecte —, et c'était la
    # seule sans le filet qui empêche un plantage d'emporter les quatorze
    # autres avant qu'une seule ligne ne soit écrite.
    with rep:
        etape("indicateurs et intérêts",
              lambda cc: indicateurs(cc, tous, rep, listes))
    # Les synthèses en DERNIER, après tous les producteurs : la synthèse des
    # adresses relit tous les faits, y compris le contexte des motifs repérés
    # dans les octets bruts.
    for nom, fn in (("périodes", periodes), ("supports amovibles", supports),
                    ("adresses réseau", adresses)):
        etape(nom, fn)

    with open(args.sortie, "w", encoding="utf-8") as fh:
        for f in FAITS:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    ecrire_csv(os.path.splitext(args.sortie)[0] + ".csv", FAITS, colonnes_csv(FAITS))

    chemin_man = os.path.splitext(args.sortie)[0] + "-manifeste.json"
    with open(chemin_man, "w", encoding="utf-8") as fh:
        man = manifeste(c, args.sortie, sys.argv, prov, signature)
        json.dump(man, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")

    par_cat = man["faits"]["par_categorie"]
    print(f"\n{len(FAITS)} faits → {args.sortie}  (+ .csv)", file=sys.stderr)
    print(f"  empreintes des pièces lues → {chemin_man}", file=sys.stderr)
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(par_cat.items())),
          file=sys.stderr)


if __name__ == "__main__":
    main()
