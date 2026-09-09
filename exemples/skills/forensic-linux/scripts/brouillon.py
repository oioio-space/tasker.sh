#!/usr/bin/env python3
"""Prépare le BROUILLON du rapport forensique : les tableaux, pas la prose.

    brouillon.py faits.jsonl [-o rapport.md] [--fuseau Europe/Paris] [--lignes 300]

Tout ce qui est tableau vient des faits, dans un ordre fixe : deux analystes
obtiennent le même brouillon. Ce qui reste à écrire est marqué « À rédiger »,
avec ce qu'il faut y dire. Le modèle rédige entre les tableaux ; il ne les
refait pas, il ne les corrige pas, il ne les complète pas de mémoire.

Chaque ligne d'événement répond à cinq questions : QUAND (dans le fuseau du
poste), QUI (le compte), QUOI, OÙ (terminal, origine, chemin) et COMMENT (la
pièce et le geste qui l'ont donnée). Les événements sont rangés par session :
ce qui s'est passé pendant qu'un compte était ouvert lui est rapproché — et
quand deux sessions se chevauchent, le brouillon le dit au lieu de choisir.

Les dates sont écrites dans le fuseau du poste (fait « fuseau horaire du
poste »), sauf --fuseau. Une date sans fuseau dans les faits — une ligne
syslog, un journal d'installation — est déjà dans l'heure du poste : elle est
recopiée telle quelle, et marquée d'un ≈ pour le dire.

Le brouillon est fait pour un modèle au contexte limité : les tableaux sont
bornés (--lignes), et chaque section se relit seule.
"""
import argparse, functools, json, os, re, sys
from datetime import datetime, timedelta, timezone

# Ce qui entre dans les sessions et la chronologie : ce qui éclaire la vie de
# la machine. La navigation a sa section ; la timeline du système de fichiers
# est trop volumineuse pour un tableau et se lit à part.
EVENEMENTS = ("evenement", "support", "telechargement", "paquet", "suspect",
              "persistance", "usage", "indicateur")
SESSION_MAX = timedelta(hours=12)      # une session sans fin connue ne dure pas plus
RE_ISO_UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)')

LEXIQUE = {
    "wtmp": "le registre binaire des ouvertures et fermetures de session, et des démarrages ; "
            "« last » le lit",
    "btmp": "le registre des tentatives de connexion refusées",
    "lastlog": "la dernière connexion de chaque compte, une par compte, écrasée à chaque fois",
    "tty": "le terminal par lequel une session est ouverte — « :0 » est l'écran, « pts/N » un "
           "terminal ou une connexion distante",
    "sudo": "commande qui exécute une action avec les droits d'un autre compte, root le plus "
            "souvent ; le journal note qui, quoi, quand",
    "su": "commande qui ouvre une session sous un autre compte, sans quitter la sienne",
    "cookie": "petit fichier qu'un site dépose dans le navigateur ; sa présence prouve une "
              "visite, même si l'historique a été vidé",
    "historique de navigation": "la liste des pages visitées, avec la date de la dernière visite et "
                                "le nombre de visites",
    "SSID": "le nom d'un réseau sans fil",
    "machine-id": "l'identifiant unique de l'installation, tiré au sort à la pose du système",
    "timeline": "la liste datée de tous les fichiers du disque : création, modification, dernier accès",
    "epoch": "un nombre de secondes depuis le 1ᵉʳ janvier 1970 : la façon dont les systèmes "
             "notent une date, sans fuseau",
    "UTC": "le temps universel ; les dates en UTC sont converties dans le fuseau du poste "
           "pour le rapport",
    "HISTTIMEFORMAT": "réglage qui fait dater par l'interpréteur chaque commande de "
                      "l'historique ; sans lui, l'historique n'a pas de dates",
    "journal systemd": "le journal central des systèmes récents : démarrages, services, "
                       "connexions, périphériques",
    "compte de domaine": "un compte géré par un annuaire central (Active Directory, LDAP) et "
                         "non par le poste",
    "photorec": "outil qui retrouve des fichiers effacés en reconnaissant leur contenu, "
                "sans leur nom ni leur date",
    "inode": "la fiche interne d'un fichier sur le disque ; un fichier effacé garde sa fiche "
             "un temps",
    "sha256": "une empreinte : deux fichiers de même empreinte ont le même contenu",
}


def lire_jsonl(chemin):
    lignes = []
    with open(chemin, encoding="utf-8") as fh:
        for l in fh:
            l = l.strip()
            if l:
                try:
                    lignes.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
    return lignes


def cellule(v, large=200):
    """Une valeur dans une case : sans barre verticale ni retour à la ligne."""
    if v is None or v == "":
        return "—"
    t = str(v).replace("|", "\\|").replace("\n", " ")
    return t if len(t) <= large else t[:large - 1] + "…"


def tableau(colonnes, lignes, large=200, borne=None, quoi="lignes"):
    if not lignes:
        return "_aucune ligne_\n"
    coupe = ""
    if borne and len(lignes) > borne:
        coupe = (f"\n_{len(lignes) - borne} {quoi} de plus ne sont pas dans ce tableau : "
                 f"`grep` sur faits.jsonl, ou `--lignes` plus grand._\n")
        lignes = lignes[:borne]
    out = ["| " + " | ".join(colonnes) + " |", "|" + "---|" * len(colonnes)]
    out += ["| " + " | ".join(cellule(x, large) for x in l) + " |" for l in lignes]
    return "\n".join(out) + "\n" + coupe


def a_rediger(quoi):
    return f"> **À rédiger** — {quoi}\n"


class Horloge:
    """Lit un horodatage de fait et le rend dans le fuseau choisi. Convertit
    aussi les dates UTC qui traînent dans une note, pour qu'un rapport ne
    mélange jamais deux fuseaux."""

    def __init__(self, nom):
        self.nom, self.zone = nom, None
        if nom:
            try:
                from zoneinfo import ZoneInfo
                self.zone = ZoneInfo(nom)
            except Exception:                                    # noqa: BLE001
                print(f"  ! fuseau « {nom} » inconnu : dates laissées telles quelles",
                      file=sys.stderr)

    @functools.lru_cache(maxsize=None)
    def lire(self, h):
        """→ (datetime naïf comparable ou None, texte à afficher)."""
        if not h:
            return None, "—"
        try:
            d = datetime.fromisoformat(str(h).replace("Z", "+00:00"))
        except ValueError:
            return None, str(h)
        if d.tzinfo is None:
            return d, f"≈ {d.isoformat(sep=' ')}"
        # tout sur une même échelle : le fuseau du poste, ou l'UTC à défaut —
        # sans quoi un +01:00 et un Z ne se comparent pas
        d = d.astimezone(self.zone or timezone.utc)
        return d.replace(tzinfo=None), d.isoformat(sep=" ")

    def quand(self, f):
        return self.lire(f.get("horodatage"))[1]

    def cle(self, f):
        return self.lire(f.get("horodatage"))[0] or datetime.max

    def tri(self, faits):
        return sorted(faits, key=lambda f: (self.cle(f), f["id"]))

    def texte(self, s):
        """Les dates UTC d'une phrase, dans le fuseau du poste."""
        if not s or not self.zone:
            return s
        return RE_ISO_UTC.sub(lambda m: self.lire(m.group(0))[1], str(s))


def hote(url):
    m = re.match(r'^[a-z]+://([^/:]+)', url or "")
    return m.group(1).lower() if m else (url or "").lower().lstrip(".")


def ou(f):
    """OÙ : ce que la note dit du terminal, de l'origine, du chemin."""
    n = f.get("note") or ""
    morceaux = re.findall(r'(tty [^\s,]+|depuis [^\s,]+|port [\d.-]+|/run/media/\S+|/dev/sd\w+)', n)
    return ", ".join(dict.fromkeys(morceaux)) or None


def sessions(faits, horloge):
    """Apparie chaque ouverture de session à sa fermeture, par terminal.

    Le binaire wtmp note la fermeture sur le même tty (type 8) ; la sortie de
    « last » écrit « fin … » dans la note. Sans l'un ni l'autre, la session
    reste ouverte au plus SESSION_MAX — et le brouillon le dit.
    """
    ouvertures, fermetures = [], []
    for f in faits:
        if f.get("categorie") != "evenement" or not f.get("horodatage"):
            continue
        if "ouverture de session" in f["fait"]:
            ouvertures.append(f)
        elif "fermeture de session" in f["fait"] or "fin de la session" in (f.get("note") or ""):
            fermetures.append(f)
    ouvertures = horloge.tri(ouvertures)
    fermetures = horloge.tri(fermetures)
    out = []
    for o in ouvertures:
        debut = horloge.cle(o)
        note = o.get("note") or ""
        tty = re.search(r'tty ([^\s,]+)', note)
        tty = tty.group(1) if tty else None
        fin, fin_texte, comment = None, None, "fin inconnue"
        m = re.search(r'fin (\S+)', note)
        if m:
            fin, fin_texte = horloge.lire(m.group(1))
            comment = "fin lue dans la sortie de last"
        elif tty:
            for fm in fermetures:
                if f"tty {tty}" in (fm.get("note") or "") and horloge.cle(fm) >= debut:
                    fin, fin_texte, comment = horloge.cle(fm), horloge.quand(fm), f"fermeture {fm['id']}"
                    break
        if fin is None:
            fin, comment = debut + SESSION_MAX, "fin inconnue : bornée à 12 h"
            fin_texte = fin.isoformat(sep=" ")
        out.append({"fait": o, "acteur": o.get("acteur"), "debut": debut, "fin": fin,
                    "fin_texte": fin_texte, "tty": tty, "comment": comment})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("faits")
    ap.add_argument("-o", "--sortie")
    ap.add_argument("--fuseau", metavar="Europe/Paris")
    ap.add_argument("--lignes", type=int, default=300, metavar="N",
                    help="lignes au plus par tableau (défaut 300) ; au-delà, le brouillon "
                         "dit combien manquent et comment les lire")
    args = ap.parse_args()

    faits = lire_jsonl(args.faits)
    man_chemin = os.path.splitext(args.faits)[0] + "-manifeste.json"
    man = {}
    if os.path.isfile(man_chemin):
        with open(man_chemin, encoding="utf-8") as fh:
            man = json.load(fh)
    prefix = man.get("collecte") or "PREFIX"
    sortie = args.sortie or f"rapport-forensic-{prefix}.md"

    par = {}
    for f in faits:
        par.setdefault(f.get("categorie"), []).append(f)

    def machine_dit(quoi):
        return next((f["valeur"] for f in par.get("machine", []) if f["fait"] == quoi), None)

    H = Horloge(args.fuseau or machine_dit("fuseau horaire du poste"))
    quand, T = H.quand, H.texte
    borne = args.lignes

    S = [f"# Rapport forensique — {prefix}\n",
         "_Brouillon produit par `brouillon.py` : les tableaux viennent des faits, "
         "la prose est à écrire aux endroits marqués. Retirez cette ligne une fois "
         "le rapport rédigé._\n",
         f"Les dates sont écrites dans le fuseau **{H.nom or 'des faits (non converti)'}**. "
         "Une date précédée de ≈ vient d'une pièce qui n'écrit pas son fuseau — "
         "une ligne syslog, un journal d'installation — et se lit dans l'heure du "
         "poste, avec l'année déduite quand le fait le dit.\n",
         "> Ce rapport désigne des **comptes** — des identités numériques. Il "
         "n'établit pas qui tenait le clavier : une collecte ne le dit jamais.\n"]

    # ── 0 ──
    S.append("## En bref\n")
    S.append(a_rediger("cinq phrases pour quelqu'un qui ne lira que ceci : quelle machine, "
                       "quels comptes l'ont fait vivre et quand, ce qui attire l'œil (une "
                       "ligne par point, avec l'identifiant du fait), ce que la collecte ne "
                       "permet pas de dire, et ce qu'il faudrait pour trancher. Pas de "
                       "jargon : le lexique en fin de rapport est là pour le reste."))

    # ── 1 ──
    S.append("## 1 · La machine\n")
    S.append(tableau(["", "", "id", "source"],
                     [(f["fait"], f["valeur"], f["id"], f["source"])
                      for f in par.get("machine", [])], borne=borne))
    S.append(a_rediger("deux phrases : ce qu'est cette machine, depuis quand elle "
                       "existe, quand elle a servi pour la dernière fois. Signalez "
                       "une horloge matérielle en heure locale si le fait le dit."))

    # ── 2 ──
    S.append("## 2 · Les comptes\n")
    sess = sessions(faits, H)
    par_compte = {}
    for x in sess:
        par_compte.setdefault(x["acteur"], []).append(x)
    lignes = []
    vus = set()
    for f in par.get("compte", []):
        if "(nombre)" in f["fait"]:
            continue
        s = par_compte.get(f["valeur"], [])
        vus.add(f["valeur"])
        lignes.append((f["valeur"], f["fait"], len(s),
                       quand(s[0]["fait"]) if s else "—", quand(s[-1]["fait"]) if s else "—",
                       f["id"]))
    for nom in sorted(k for k in par_compte if k and k not in vus):
        s = par_compte[nom]
        lignes.append((nom, "a ouvert des sessions sans figurer dans passwd", len(s),
                       quand(s[0]["fait"]), quand(s[-1]["fait"]), s[0]["fait"]["id"]))
    S.append(tableau(["compte", "nature", "sessions", "première", "dernière", "id"],
                     lignes, borne=borne))
    S.append(a_rediger("ce qui distingue un compte qui a servi d'un compte qui "
                       "existe. Un compte sans session n'est pas un compte inutilisé "
                       "si wtmp a été tourné : voir les limites."))

    # ── 3 ──
    S.append("## 3 · Le domaine\n")
    S.append(tableau(["", "", "id", "source"],
                     [(f["fait"], f["valeur"], f["id"], f["source"])
                      for f in par.get("domaine", [])], borne=borne))
    S.append(a_rediger("l'appartenance au domaine est-elle prouvée (keytab, cache "
                       "sss) ou seulement configurée ?"))

    # ── 4 ──
    S.append("## 4 · Le réseau\n")
    S.append(tableau(["", "valeur", "compte", "date", "id"],
                     [(f["fait"], f["valeur"], f.get("acteur"), quand(f), f["id"])
                      for f in par.get("reseau", [])], borne=borne))
    S.append(a_rediger("une phrase : où cette machine vivait (réseau, DNS, "
                       "passerelle), et si elle a connu d'autres réseaux."))

    # ── 5 ──
    S.append("## 5 · Ce qui s'est passé, session par session\n")
    S.append("Une session, c'est un compte ouvert sur un terminal entre deux instants. "
             "Ce qui arrive dans cette fenêtre lui est **rapproché** — pas prouvé : quand "
             "deux sessions se chevauchent, la ligne le dit, et l'attribution reste à "
             "établir par une autre trace (le chemin `/run/media/<compte>/`, le compte "
             "d'un sudo).\n")
    evenements = H.tri([f for f in faits if f.get("categorie") in EVENEMENTS
                        and f.get("horodatage") and "ouverture de session" not in f["fait"]
                        and "fermeture de session" not in f["fait"]])
    colonnes = ["quand", "qui", "quoi", "valeur", "où", "comment", "confiance", "id"]

    def ligne(f, simultane=False):
        qui = f.get("acteur") or ("? (session simultanée)" if simultane else "—")
        return (quand(f), qui, f["fait"], T(f["valeur"]), ou(f),
                f"{f['source']} · {f['methode']}", f.get("confiance"), f["id"])

    places = set()
    for i, x in enumerate(sess):
        chevauche = [y for y in sess if y is not x and y["debut"] < x["fin"] and y["fin"] > x["debut"]
                     and y["acteur"] != x["acteur"]]
        dedans = [f for f in evenements if x["debut"] <= H.cle(f) <= x["fin"]
                  and (not f.get("acteur") or f["acteur"] == x["acteur"])]
        S.append(f"### {x['acteur'] or '?'} — du {quand(x['fait'])} au "
                 f"{x['fin_texte']} ({x['comment']}"
                 + (f", tty {x['tty']}" if x["tty"] else "") + f", {x['fait']['id']})\n")
        if chevauche:
            S.append("_Sessions simultanées : " + ", ".join(
                f"{y['acteur']} ({y['fait']['id']})" for y in chevauche)
                + " — les lignes sans compte ne sont attribuables à aucune des deux._\n")
        if dedans:
            S.append(tableau(colonnes, [ligne(f, bool(chevauche)) for f in dedans],
                             borne=min(borne, 60), quoi="événements de cette session"))
            places.update(f["id"] for f in dedans)
        else:
            S.append("_Rien d'autre dans cette fenêtre._\n")
    hors = [f for f in evenements if f["id"] not in places]
    S.append("### Hors de toute session ouverte\n")
    S.append("Démarrages, tâches automatiques, ou sessions dont wtmp n'a pas gardé la trace.\n")
    S.append(tableau(colonnes, [ligne(f) for f in hors], borne=borne, quoi="événements"))
    S.append(a_rediger("par session, une phrase : ce que le compte a fait, avec les "
                       "identifiants. Retirez le bruit (cron, mises à jour automatiques) "
                       "en disant ce que vous retirez. Une ligne « ? (session "
                       "simultanée) » ne s'attribue à personne sans une autre trace."))

    # ── 6 ──
    S.append("## 6 · La navigation et les téléchargements\n")
    nav_par = {}
    for f in par.get("navigation", []) + par.get("telechargement", []) + \
            [f for f in par.get("usage", []) if "navigateur" in f["fait"]]:
        nav_par.setdefault(f.get("acteur") or "?", []).append(f)
    for compte in sorted(nav_par):
        liste = nav_par[compte]
        S.append(f"### {compte}\n")
        pages, cookies, charges, secrets = [], [], [], []
        for f in liste:
            if f["fait"] == "page visitée":
                pages.append(f)
            elif f["fait"] == "domaine ayant posé un cookie":
                cookies.append(f)
            elif f["categorie"] == "telechargement":
                charges.append(f)
            elif "mot de passe" in f["fait"]:
                secrets.append(f)
        visites = {}
        for f in pages:
            note = f.get("note") or ""
            m = re.match(r'(\d+) visite', note)
            premiere = re.search(r'la première le (\S+)', note)
            v = visites.setdefault(hote(f["valeur"]), [0, []])
            v[0] += int(m.group(1)) if m else 1
            v[1].append(f.get("horodatage"))
            if premiere:
                v[1].append(premiere.group(1))
        lignes = []
        for h, (n, dates) in sorted(visites.items(), key=lambda x: (-x[1][0], x[0]))[:25]:
            d = sorted(x for x in dates if x)
            lignes.append((h, n, H.lire(d[0])[1] if d else "—", H.lire(d[-1])[1] if d else "—"))
        S.append(f"**{len(pages)} pages** dans l'historique, {len(cookies)} domaines "
                 f"à cookie, {len(charges)} téléchargements. Domaines les plus visités :\n")
        S.append(tableau(["domaine", "visites", "première page", "dernière page"], lignes))
        # le recoupement que le skill demande : un cookie sans page d'historique
        hotes_pages = {hote(f["valeur"]) for f in pages}
        orphelins = []
        for f in cookies:
            hc = hote(f["valeur"]).lstrip(".")
            if not any(hc.endswith(h) or h.endswith(hc) for h in hotes_pages):
                orphelins.append(f)
        if orphelins:
            S.append("**Cookies sans page d'historique** — une visite dont la trace "
                     "d'historique a disparu, ou qui vient d'une page tierce :\n")
            S.append(tableau(["domaine", "dernier accès", "id"],
                             [(f["valeur"], quand(f), f["id"]) for f in H.tri(orphelins)],
                             borne=borne))
        if charges:
            S.append("**Téléchargements** :\n")
            S.append(tableau(["date", "fichier", "origine", "id"],
                             [(quand(f), f["valeur"], (f.get("note") or "").replace("depuis ", ""),
                               f["id"]) for f in H.tri(charges)], borne=borne))
        if secrets:
            S.append("**Sites avec un mot de passe enregistré dans le navigateur** "
                     "(le site seul est lu) :\n")
            S.append(tableau(["site", "dernier usage", "id"],
                             [(f["valeur"], quand(f), f["id"]) for f in H.tri(secrets)],
                             borne=borne))
    if not nav_par:
        S.append("_Aucune base de navigateur dans les faits._\n")
    S.append(a_rediger("par compte : l'usage qui se dégage, daté. Un téléchargement "
                       "se recoupe avec l'apparition du fichier dans la timeline ; "
                       "citez les deux ou dites que le second manque."))

    # ── 7 ──
    S.append("## 7 · Les supports amovibles\n")
    S.append(tableau(["date", "fait", "valeur", "compte", "id"],
                     [(quand(f), f["fait"], f["valeur"], f.get("acteur"), f["id"])
                      for f in H.tri(par.get("support", []))], borne=borne))
    S.append(a_rediger("par support : branchement, numéro de série, modèle, "
                       "montage (le chemin /run/media/<compte>/ nomme le compte), "
                       "débranchement — puis ce qui a été lu ou écrit dessus "
                       "(timeline, recently-used.xbel). Sans cela : « ce qui y a "
                       "été copié n'est pas établi »."))

    # ── 8 ──
    S.append("## 8 · Ce qui attire l'œil\n")
    S.append(tableau(["date", "constat", "valeur", "compte", "confiance", "id", "à vérifier"],
                     [(quand(f), f["fait"], f["valeur"], f.get("acteur"), f.get("confiance"),
                       f["id"], "…") for f in H.tri(par.get("suspect", []))], borne=borne))
    if par.get("indicateur"):
        S.append("### Les indicateurs cherchés\n")
        S.append("Ce que l'analyste a demandé de chercher (`--indicateurs`), trouvé ou non :\n")
        S.append(tableau(["indicateur", "résultat", "où", "note", "id"],
                         [(f["valeur"], f["fait"], f["source"], T(f.get("note")), f["id"])
                          for f in par["indicateur"]], borne=borne))
    S.append(a_rediger("remplissez « à vérifier » : ce qui rendrait chaque ligne "
                       "vraie ou fausse. N'affirmez pas une compromission. Retirez "
                       "ce qui est banal en le disant."))

    # ── 9 ──
    S.append("## 9 · Les limites\n")
    S.append(tableau(["limite", "valeur", "note", "id"],
                     [(f["fait"], f["valeur"], T(f.get("note")), f["id"])
                      for f in par.get("limite", [])], borne=borne))
    reprises = []
    for f in par.get("limite", []):
        m = re.search(r"à reprendre sur l'image montée : (.+?)\. Étape de collecte-linux\.conf : « (.+?) »",
                      f.get("note") or "")
        if m:
            reprises.append((f["valeur"], m.group(1), m.group(2), f["id"]))
    if reprises:
        S.append("### Demande de reprise\n")
        S.append("Pièces absentes que la collecte sait reprendre. À transmettre telle quelle "
                 "à qui a l'image ; le numéro de chaque étape se lit dans le plan :\n")
        S.append("    sudo ./tasker.sh -c exemples/collecte-linux.conf -l --set MONTAGE=… --set PERIPH=…\n"
                 "    sudo ./tasker.sh -c exemples/collecte-linux.conf --only <numéros> --set MONTAGE=… --set PERIPH=…\n")
        S.append(tableau(["pièce", "chemin sur le système d'origine", "étape à rejouer", "id"],
                         reprises, borne=borne))
        S.append("Une pièce reprise à la main se pose dans le dossier de la collecte, sous "
                 "le nom que l'extracteur attend (`references/ou-chercher.md`), puis "
                 "l'extraction se relance.\n")
    S.append(a_rediger("pour chaque pièce manquante : le système ne l'avait pas, "
                       "ou la collecte l'a ratée ? (PREFIX_rapport.txt de la "
                       "collecte tranche). Les trous de journaux : première et "
                       "dernière date de chaque source. Ce que la mémoire vive et "
                       "le réseau auraient dit."))

    # ── 10 ──
    S.append("## 10 · Annexe : méthode\n")
    outil = man.get("outil") or {}
    S.append(tableau(["", ""], [
        ("commande", f"`{man.get('commande')}`" if man.get("commande") else None),
        ("extracteur", outil.get("fichier")),
        ("empreinte de l'extracteur", outil.get("sha256")),
        ("empreinte des faits", man.get("faits_sha256")),
        ("faits", len(faits)),
        ("pièces lues", len(man.get("pieces_lues") or {})),
    ]))
    S.append(tableau(["catégorie", "faits"], sorted((k, len(v)) for k, v in par.items())))
    S.append("### Pièces lues\n")
    S.append(tableau(["pièce", "sha256", "octets"],
                     [(p, v.get("sha256"), v.get("octets"))
                      for p, v in sorted((man.get("pieces_lues") or {}).items())], borne=borne))
    S.append("### Table des faits cités\n")
    S.append(a_rediger("une ligne par fait cité dans le rapport : id, source, "
                       "méthode — recopiés de faits.jsonl, jamais réécrits."))

    # ── 11 ──
    corps = "\n".join(S).lower()
    termes = [(t, d) for t, d in LEXIQUE.items() if t.lower() in corps]
    S.append("## 11 · Lexique\n")
    S.append("Les termes techniques employés ci-dessus, pour un lecteur qui n'est pas du métier.\n")
    S.append(tableau(["terme", "ce que c'est"], termes))

    with open(sortie, "w", encoding="utf-8") as fh:
        fh.write("\n".join(S))
    print(f"{sortie} : {len(faits)} faits, {len(sess)} sessions, "
          f"{sum(x.startswith('> **À rédiger**') for x in S)} passages à rédiger",
          file=sys.stderr)


if __name__ == "__main__":
    main()
