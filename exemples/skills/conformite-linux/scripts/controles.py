#!/usr/bin/env python3
"""Relève des CONSTATS objectifs dans une collecte, pour les confronter à une charte.

    controles.py <dossier de collecte> [-o constats.jsonl]

Un constat n'est pas un manquement. « PermitRootLogin yes » est un fait ; qu'il
soit interdit dépend de la charte, que ce script ne connaît pas. Le rapprochement
est le travail du rapport, et il doit être visible.

Chaque constat porte donc : ce qui est observé, où, par quel geste, et la
question à laquelle une règle devra répondre pour en faire un manquement.

Bibliothèque standard seulement. La collecte n'est jamais modifiée.
"""
import argparse, base64, hashlib, json, os, re, sys, tarfile
from datetime import datetime, timezone

CONSTATS = []
_N = [0]


def constat(theme, quoi, valeur, source, methode, acteur=None, portee=None,
            question=None, note=None):
    """Pose un constat.

    theme    la famille : comptes, authentification, secrets, durcissement, usage
    quoi     ce qui est observé, formulé sans jugement
    portee   « poste » ou « compte » — un manquement de poste n'est imputable
             à personne en particulier
    question ce qu'une règle devra dire pour en faire un manquement
    """
    _N[0] += 1
    c = {"id": f"C{_N[0]:04d}", "theme": theme, "constat": quoi, "valeur": valeur,
         "source": source, "methode": methode,
         "portee": portee or ("compte" if acteur else "poste")}
    for k, v in (("acteur", acteur), ("question", question), ("note", note)):
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
    for prof in c.chercher("_profils.tar.gz", "COMPTES"):
        compte = _compte_de(prof, "profils.tar.gz")
        for nom, blob in c.membres_tar(prof):
            base = os.path.basename(nom)
            if base not in ("places.sqlite", "History", "cookies.sqlite", "Cookies"):
                continue
            texte = blob.decode("latin-1", "replace")
            for famille, motif in FAMILLES:
                for m in set(motif.findall(texte)):
                    cle = (compte, famille, m.lower())
                    if cle in vus:
                        continue
                    vus[cle] = True
                    constat("usage", f"service {famille} présent dans un "
                            "profil de navigateur", m,
                            f"{c.rel(prof)} → {nom}",
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

    inv = c.chercher("_inventaire.txt", "COMPTES")
    for f in inv:
        compte = _compte_de(f, "inventaire.txt")
        txt = c.texte(f, 4_000_000)
        for m in set(re.findall(r'\S+\.(?:AppImage|deb|rpm|exe|msi)\b', txt)):
            constat("usage", "programme installable présent dans un dossier "
                    "personnel", m, c.rel(f), "recherche d'extensions dans "
                    "l'inventaire du profil", acteur=compte,
                    question="la charte réserve-t-elle l'installation de "
                             "logiciels au service informatique ?")


# ── mise en ordre ────────────────────────────────────────────────────
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
    print("\n  Un constat n'est pas un manquement : il le devient quand une règle\n"
          "  de la charte le dit. Voir le SKILL.md.", file=sys.stderr)


if __name__ == "__main__":
    main()
