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

Le brouillon est fait pour un modèle au contexte limité : les tableaux sont
bornés (--lignes), et chaque section se relit seule.
"""
import argparse, bisect, json, os, re, sys
from datetime import datetime, timedelta, timezone

# ── commun ── (identique dans forensic-linux et conformite-linux : chaque skill
# s'installe seul, et le README dit comment vérifier que le bloc n'a pas dérivé)
RE_ISO_UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)')


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


def tableau(colonnes, lignes, large=200, borne=None, quoi="lignes", fichier="le fichier"):
    if not lignes:
        return "_aucune ligne_\n"
    coupe = ""
    if borne and len(lignes) > borne:
        coupe = (f"\n_{len(lignes) - borne} {quoi} de plus ne sont pas dans ce tableau : "
                 f"`grep` sur {fichier}, ou `--lignes` plus grand._\n")
        lignes = lignes[:borne]
    out = ["| " + " | ".join(colonnes) + " |", "|" + "---|" * len(colonnes)]
    out += ["| " + " | ".join(cellule(x, large) for x in l) + " |" for l in lignes]
    return "\n".join(out) + "\n" + coupe


def a_rediger(quoi):
    return f"> **À rédiger** — {quoi}\n"


class Horloge:
    """Lit un horodatage et le rend dans le fuseau du poste, sur une seule
    échelle comparable. Convertit aussi les dates UTC qui traînent dans une
    note, pour qu'un rapport ne mélange jamais deux fuseaux.

    Trois formes existent : « …Z » (epoch, UTC), « …+01:00 » (journalctl), et
    rien — une ligne syslog, dpkg.log : c'est l'heure du poste, recopiée telle
    quelle et marquée ≈. Un jour seul (« 2026-01-03 ») reste un jour.
    """

    def __init__(self, nom):
        self.nom, self.zone, self._cache = nom, None, {}
        if nom:
            try:
                from zoneinfo import ZoneInfo
                self.zone = ZoneInfo(nom)
            except Exception:                                    # noqa: BLE001
                print(f"  ! fuseau « {nom} » inconnu : dates laissées telles quelles",
                      file=sys.stderr)

    def lire(self, h):
        """→ (datetime naïf comparable ou None, texte à afficher)."""
        if h in self._cache:
            return self._cache[h]
        r = self._lire(h)
        self._cache[h] = r
        return r

    def _lire(self, h):
        if not h:
            return None, "—"
        h = str(h)
        try:
            d = datetime.fromisoformat(h.replace("Z", "+00:00"))
        except ValueError:
            return None, h
        if len(h) == 10:
            return d, h
        if d.tzinfo is None:
            return d, f"≈ {d.isoformat(sep=' ')}"
        d = d.astimezone(self.zone or timezone.utc)
        return d.replace(tzinfo=None), d.isoformat(sep=" ")

    def quand(self, f):
        return self.lire(f.get("horodatage") or f.get("date"))[1]

    def cle(self, f):
        return self.lire(f.get("horodatage") or f.get("date"))[0] or datetime.max

    def tri(self, faits):
        return sorted(faits, key=lambda f: (self.cle(f), f["id"]))

    def texte(self, s):
        """Les dates UTC d'une phrase, dans le fuseau du poste."""
        if not s or not self.zone:
            return s
        return RE_ISO_UTC.sub(lambda m: self.lire(m.group(0))[1], str(s))


def fuseau_des_faits(faits):
    return next((f["valeur"] for f in faits if f.get("fait") == "fuseau horaire du poste"), None)
# ── fin commun ──


# Ce qui entre dans les sessions et la chronologie : ce qui éclaire la vie de
# la machine. La navigation a sa section ; la timeline du système de fichiers
# est trop volumineuse pour un tableau et se lit à part.
EVENEMENTS = ("evenement", "support", "telechargement", "paquet", "suspect",
              "persistance", "usage", "timeline")
SESSION_MAX = timedelta(hours=12)      # une session sans fin connue ne dure pas plus
RE_OU = re.compile(r'(tty [^\s,]+|depuis [^\s,]+|port [\d.-]+|/run/media/\S+|/dev/sd\w+)')
RE_VISITES = re.compile(r'(\d+) visite')
RE_PREMIERE = re.compile(r'la première le (\S+)')
RE_REPRISE = re.compile(r"à reprendre sur l'image montée : (.+?)\. Étape de collecte-linux\.conf : « (.+?) »")

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
    "macb": "les quatre dates d'un fichier : m contenu modifié, a contenu lu, c droits ou nom "
            "changés, b fichier créé — « ...b » est une création, « m.c. » une écriture",
    "inode": "la fiche interne d'un fichier sur le disque ; deux noms de même inode sont le "
             "même fichier",
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
    "snap": "une application livrée avec tout ce qu'il lui faut, hors du gestionnaire de "
            "paquets : elle n'apparaît ni dans dpkg ni dans rpm",
    "flatpak": "comme un snap : une application installable sans droits d'administration, "
               "invisible à la liste des paquets",
    "unité systemd": "un fichier qui déclare un programme à lancer au démarrage, ou à une "
                     "heure donnée ; celles de /usr viennent des paquets, celles de /etc "
                     "ont été posées à la main",
    "autostart": "un fichier .desktop qui lance un programme à l'ouverture de session — "
                 "celui du compte s'il est dans son dossier personnel",
    "udev": "les règles déclenchées au branchement d'un matériel ; une règle peut lancer "
            "un programme",
    "marque-page": "un signet enregistré dans le navigateur : un choix délibéré, daté, "
                   "qui survit au vidage de l'historique",
    "formulaire": "ce que le compte a TAPÉ dans une page — recherches, adresses — que le "
                  "navigateur retient pour le proposer ensuite",
    "inode": "la fiche interne d'un fichier sur le disque ; un fichier effacé garde sa fiche "
             "un temps",
    "sha256": "une empreinte : deux fichiers de même empreinte ont le même contenu",
}


def hote(url):
    m = re.match(r'^[a-z]+://([^/:]+)', url or "")
    return m.group(1).lower() if m else (url or "").lower().lstrip(".")


def ou(f):
    """OÙ : les champs structurés du fait, ou ce que la note en dit."""
    morceaux = [f"tty {f['tty']}" if f.get("tty") else None,
                f"depuis {f['origine']}" if f.get("origine") else None]
    morceaux = [x for x in morceaux if x] or RE_OU.findall(f.get("note") or "")
    return ", ".join(dict.fromkeys(morceaux)) or None


def sessions(faits, H):
    """Apparie chaque ouverture de session à sa fermeture.

    L'extracteur pose la fin en champ quand la pièce la donne (wtmp.db, sortie
    de « last ») ; le binaire wtmp note la fermeture sur le même tty. Sans l'un
    ni l'autre, la session reste ouverte au plus SESSION_MAX — et le brouillon
    le dit.
    """
    ouvertures, fermetures = [], {}
    for f in faits:
        if f.get("categorie") != "evenement" or not f.get("horodatage"):
            continue
        if "ouverture de session" in f["fait"]:
            ouvertures.append(f)
        elif "fermeture de session" in f["fait"] or "fin de la session" in (f.get("note") or ""):
            tty = f.get("tty") or (RE_OU.search(f.get("note") or "") or [None, ""])[1][4:]
            fermetures.setdefault(tty, []).append((H.cle(f), f["id"]))
    for liste in fermetures.values():
        liste.sort()
    out = []
    for o in H.tri(ouvertures):
        debut = H.cle(o)
        tty = o.get("tty") or (re.search(r'tty ([^\s,]+)', o.get("note") or "") or [None, None])[1]
        if o.get("fin"):
            fin, comment = H.lire(o["fin"])[0], "fin donnée par la pièce"
        else:
            fin, comment = None, None
            i = bisect.bisect_left(fermetures.get(tty, []), (debut, ""))
            if i < len(fermetures.get(tty, [])):
                fin, comment = fermetures[tty][i][0], f"fermeture {fermetures[tty][i][1]}"
        if fin is None:
            fin, comment = debut + SESSION_MAX, "fin inconnue : bornée à 12 h"
        out.append({"fait": o, "acteur": o.get("acteur"), "debut": debut, "fin": fin,
                    "tty": tty, "comment": comment})
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
    borne = args.lignes

    par, confirme = {}, {}
    for f in faits:
        par.setdefault(f.get("categorie"), []).append(f)
        if f.get("confirme"):
            confirme.setdefault(f["confirme"], []).append(f)
    H = Horloge(args.fuseau or fuseau_des_faits(faits))
    quand, T = H.quand, H.texte

    def date_nue(iso):
        """L'heure du poste pour un horodatage NU — « premiere », « derniere ».

        H.quand attend un fait entier ; ces champs-là n'en sont pas. Leur en
        fabriquer un pour l'occasion se lisait comme une bizarrerie.
        """
        return H.lire(iso)[1] if iso else None

    def table(colonnes, lignes, **kw):
        return tableau(colonnes, lignes, borne=borne, fichier="faits.jsonl", **kw)

    S = [f"# Rapport forensique — {prefix}\n",
         "_Brouillon produit par `brouillon.py` : les tableaux viennent des faits, "
         "la prose est à écrire aux endroits marqués. Retirez cette ligne une fois "
         "le rapport rédigé._\n",
         f"Les dates sont écrites dans le fuseau **{H.nom or 'UTC, faute de fuseau connu'}**. "
         "Une date précédée de ≈ vient d'une pièce qui n'écrit pas son fuseau — "
         "une ligne syslog, un journal d'installation — et se lit dans l'heure du "
         "poste, avec l'année déduite quand le fait le dit.\n",
         "> Ce rapport désigne des **comptes** — des identités numériques. Il "
         "n'établit pas qui tenait le clavier : une collecte ne le dit jamais.\n"]

    S.append("## En bref\n")
    S.append(a_rediger("cinq phrases pour quelqu'un qui ne lira que ceci : quelle machine, "
                       "quels comptes l'ont fait vivre et quand, ce qui attire l'œil (une "
                       "ligne par point, avec l'identifiant du fait), ce que la collecte ne "
                       "permet pas de dire, et ce qu'il faudrait pour trancher. Pas de "
                       "jargon : le lexique en fin de rapport est là pour le reste."))

    S.append("## 1 · La machine\n")
    S.append(table(["", "", "id", "source"],
                   [(f["fait"], f["valeur"], f["id"], f["source"]) for f in par.get("machine", [])]))
    S.append(a_rediger("deux phrases : ce qu'est cette machine, depuis quand elle "
                       "existe, quand elle a servi pour la dernière fois. Signalez "
                       "une horloge matérielle en heure locale si le fait le dit."))

    S.append("## 2 · Les comptes\n")
    sess = sessions(faits, H)
    par_compte = {}
    for x in sess:
        par_compte.setdefault(x["acteur"], []).append(x)
    # « dernière écriture dans le dossier du compte » est une date, pas une
    # nature : la mettre ici lui collait les dates de session du compte, qui ne
    # sont pas les siennes. Elle est déjà dans le tableau qui suit, avec sa
    # source. Ce tableau-ci répond à une seule question : quels comptes, de
    # quelle sorte, et quand ont-ils ouvert une session.
    NATURES = ("compte local ouvrant une session", "compte de service avec un shell",
               "compte de domaine vu sur la machine", "compte sans mot de passe",
               "adresse de courriel configurée")
    lignes, vus = [], set()
    for f in par.get("compte", []):
        if "(nombre)" in f["fait"] or f["fait"] not in NATURES:
            continue
        s = par_compte.get(f["valeur"], [])
        vus.add(f["valeur"])
        lignes.append((f["valeur"], f["fait"], len(s),
                       quand(s[0]["fait"]) if s else "—", quand(s[-1]["fait"]) if s else "—",
                       f["source"], f["id"]))
    for nom in sorted(k for k in par_compte if k and k not in vus):
        s = par_compte[nom]
        lignes.append((nom, "a ouvert des sessions sans figurer dans passwd", len(s),
                       quand(s[0]["fait"]), quand(s[-1]["fait"]),
                       s[0]["fait"]["source"], s[0]["fait"]["id"]))
    S.append(table(["compte", "nature", "sessions", "première", "dernière",
                    "source", "id"], lignes))
    propres = [f for f in par.get("paquet", []) + par.get("compte", []) + par.get("persistance", [])
               if f.get("acteur") and f["fait"] not in ("compte local ouvrant une session",
                                                        "compte de service avec un shell",
                                                        "compte de domaine vu sur la machine")]
    if propres:
        S.append("**Ce qui est propre à chaque compte** — applications installées hors du "
                 "gestionnaire de paquets, courriel configuré, programmes lancés à "
                 "l'ouverture de sa session.\n")
        S.append(table(["compte", "quoi", "valeur", "source", "id"],
                       [(f["acteur"], f["fait"], f["valeur"], f["source"], f["id"])
                        for f in sorted(propres, key=lambda f: (f["acteur"], f["fait"]))]))
    S.append(a_rediger("ce qui distingue un compte qui a servi d'un compte qui "
                       "existe. Un compte sans session n'est pas un compte inutilisé "
                       "si wtmp a été tourné : voir les limites."))

    S.append("## 3 · Le domaine\n")
    S.append(table(["", "", "id", "source"],
                   [(f["fait"], f["valeur"], f["id"], f["source"]) for f in par.get("domaine", [])]))
    S.append(a_rediger("l'appartenance au domaine est-elle prouvée (keytab, cache "
                       "sss) ou seulement configurée ?"))

    S.append("## 4 · Le réseau\n")
    S.append(table(["", "valeur", "compte", "date", "id"],
                   [(f["fait"], f["valeur"], f.get("acteur"), quand(f), f["id"])
                    for f in par.get("reseau", [])]))
    S.append(a_rediger("une phrase : où cette machine vivait (réseau, DNS, "
                       "passerelle), et si elle a connu d'autres réseaux."))

    if par.get("adresse"):
        S.append("\n**Toutes les adresses relevées, et d'où elles sortent.** Les "
                 "lignes ci-dessus disent la configuration ; celles-ci rassemblent "
                 "*chaque* adresse vue n'importe où dans la collecte — profils "
                 "réseau, journaux, navigation, octets bruts du disque.\n")
        S.append("> **La colonne « vue dans » est la colonne qui compte.** La même "
                 "adresse dans un profil réseau, dans une ligne de journal et dans "
                 "les octets du disque ne dit pas la même chose : une configuration, "
                 "une connexion datée, une trace sans date ni auteur. Une adresse "
                 "qui ne vient que des octets bruts établit qu'elle a été écrite sur "
                 "ce disque — **ni quand, ni par quel logiciel, ni pour quel "
                 "compte**.\n")
        for genre, quoi in (("IP", "Adresses IP"), ("MAC", "Adresses MAC"),
                            ("URL", "Hôtes web")):
            lignes = [f for f in par["adresse"] if f.get("genre") == genre]
            if not lignes:
                continue
            S.append(f"\n*{quoi}*\n")
            S.append(table(["adresse", "portée", "vue dans", "faits", "pièces",
                            "première", "dernière", "confiance", "id"],
                           [(f["valeur"], f.get("portee"), f.get("ou"),
                             f.get("occurrences"), f.get("pieces"),
                             date_nue(f.get("premiere")), date_nue(f.get("derniere")),
                             f.get("confiance"), f["id"]) for f in lignes],
                           quoi=quoi.lower()))
        S.append(a_rediger("les adresses qui comptent, et pourquoi. Une IP privée "
                           "est le réseau local et ne prouve rien à elle seule ; une "
                           "IP publique est un contact vers l'extérieur, à dater par "
                           "une pièce qui porte une date. Une adresse MAC « tirée au "
                           "hasard » ne suit pas une machine d'un réseau à l'autre : "
                           "ne l'employez pas pour identifier un matériel. Rayez ce "
                           "qui est banal — passerelle, DNS du fournisseur, dépôt de "
                           "paquets — en le disant."))

    # Cette section sort TOUJOURS, même sans un seul fait daté. La rendre
    # conditionnelle faisait sauter le rapport de 4 à 6, et un renvoi « voir le
    # §10 » ne désignait plus la même section d'une collecte à l'autre — sans
    # compter qu'une collecte sans aucune date est justement ce qu'il faut dire.
    S.append("## 5 · Quand le poste a laissé des traces\n")
    if not par.get("periode"):
        S.append("La collecte ne porte pas assez de faits datés pour situer une "
                 "période d'usage. **Ce n'est pas un constat sur le poste** : c'est "
                 "un constat sur les pièces. Dites-le au §10 et cherchez pourquoi — "
                 "`wtmp` tourné, journaux purgés, pièces manquantes.\n")
    else:
        bornes = [f for f in par["periode"] if not f.get("jours")]
        trous = [f for f in par["periode"] if f.get("jours")]
        if bornes:
            S.append(table(["borne", "date", "tirée du fait", "source", "id"],
                           [(f["fait"], f["valeur"], f.get("depuis"), f["source"],
                             f["id"]) for f in bornes]))
        if trous:
            S.append("\n**Les périodes sans aucune trace**, toutes pièces confondues :\n")
            S.append(table(["durée", "période", "bornée par", "id"],
                           [(f"{f['jours']} jours", f["valeur"],
                             f"{f.get('depuis')} → {f.get('jusqu')}", f["id"])
                            for f in trous]))
        S.append("> **Un trou n'est pas une preuve de non-usage.** `wtmp` est tourné, "
                 "les journaux sont purgés, et un usage qui n'écrit rien ne laisse "
                 "rien. Ces lignes disent que la collecte ne porte aucune trace sur "
                 "la période — pas que le poste est resté éteint. Confrontez-les aux "
                 "limites du §10 avant d'en tirer quoi que ce soit.\n")
        S.append(a_rediger("une phrase par trou : ce qui pourrait l'expliquer, et ce "
                           "qu'il faudrait pour trancher — la date de rotation de "
                           "wtmp, la rétention du journal, un congé connu. Si vous "
                           "n'avez rien, écrivez que vous n'avez rien."))

    S.append("## 6 · Ce qui s'est passé, session par session\n")
    S.append("Une session, c'est un compte ouvert sur un terminal entre deux instants. "
             "Ce qui arrive dans cette fenêtre lui est **rapproché** — pas prouvé : quand "
             "deux sessions se chevauchent, la ligne le dit, et l'attribution reste à "
             "établir par une autre trace (le chemin `/run/media/<compte>/`, le compte "
             "d'un sudo).\n")
    evenements = H.tri([f for f in faits if f.get("categorie") in EVENEMENTS
                        and f.get("horodatage") and "ouverture de session" not in f["fait"]
                        and "fermeture de session" not in f["fait"]])
    cles = [H.cle(f) for f in evenements]
    colonnes = ["quand", "qui", "quoi", "valeur", "où", "comment", "confiance", "id"]

    def ligne(f, simultane=False):
        qui = f.get("acteur") or ("? (session simultanée)" if simultane else "—")
        return (quand(f), qui, f["fait"], T(f["valeur"]), ou(f),
                f"{f['source']} · {f['methode']}", f.get("confiance"), f["id"])

    places = set()
    for x in sess:
        chevauche = [y for y in sess if y is not x and y["debut"] < x["fin"] and y["fin"] > x["debut"]
                     and y["acteur"] != x["acteur"]]
        i, j = bisect.bisect_left(cles, x["debut"]), bisect.bisect_right(cles, x["fin"])
        dedans = [f for f in evenements[i:j] if not f.get("acteur") or f["acteur"] == x["acteur"]]
        S.append(f"### {x['acteur'] or '?'} — du {quand(x['fait'])} au "
                 f"{x['fin'].isoformat(sep=' ')} ({x['comment']}"
                 + (f", tty {x['tty']}" if x["tty"] else "") + f", {x['fait']['id']})\n")
        if chevauche:
            S.append("_Sessions simultanées : " + ", ".join(
                f"{y['acteur']} ({y['fait']['id']})" for y in chevauche)
                + " — les lignes sans compte ne sont attribuables à aucune des deux._\n")
        if dedans:
            S.append(tableau(colonnes, [ligne(f, bool(chevauche)) for f in dedans],
                             borne=min(borne, 60), quoi="événements de cette session",
                             fichier="faits.jsonl"))
            places.update(f["id"] for f in dedans)
        else:
            S.append("_Rien d'autre dans cette fenêtre._\n")
    hors = [f for f in evenements if f["id"] not in places]
    S.append("### Hors de toute session ouverte\n")
    S.append("Démarrages, tâches automatiques, ou sessions dont wtmp n'a pas gardé la trace.\n")
    S.append(table(colonnes, [ligne(f) for f in hors], quoi="événements"))
    S.append(a_rediger("par session, une phrase : ce que le compte a fait, avec les "
                       "identifiants. Retirez le bruit (cron, mises à jour automatiques) "
                       "en disant ce que vous retirez. Une ligne « ? (session "
                       "simultanée) » ne s'attribue à personne sans une autre trace."))

    S.append("## 7 · La navigation et les téléchargements\n")
    # les saisies de formulaire sont dans « usage » : un compte dont l'historique
    # a été vidé mais dont les frappes restent doit garder sa section
    usage_nav = [f for f in par.get("usage", [])
                 if f["fait"] in ("saisie dans un formulaire", "fichier ouvert récemment")
                 or "navigateur" in f["fait"]]
    comptes_nav = sorted({f.get("acteur") or "?" for f in par.get("navigation", [])
                          + par.get("telechargement", []) + usage_nav})
    for compte in comptes_nav:
        mien = lambda liste: [f for f in liste if (f.get("acteur") or "?") == compte]   # noqa: E731
        pages = [f for f in mien(par.get("navigation", [])) if f["fait"] == "page visitée"]
        cookies = [f for f in mien(par.get("navigation", [])) if f["fait"] == "domaine ayant posé un cookie"]
        charges = mien(par.get("telechargement", []))
        secrets = [f for f in mien(par.get("usage", [])) if "mot de passe" in f["fait"]]
        S.append(f"### {compte}\n")
        visites, dates_par_hote = {}, {}
        for f in pages:
            note = f.get("note") or ""
            m, premiere, h = RE_VISITES.match(note), RE_PREMIERE.search(note), hote(f["valeur"])
            visites[h] = visites.get(h, 0) + (int(m.group(1)) if m else 1)
            d = dates_par_hote.setdefault(h, [])
            d.append(f.get("horodatage"))
            if premiere:
                d.append(premiere.group(1))
        lignes = []
        for h, n in sorted(visites.items(), key=lambda x: (-x[1], x[0])):
            d = sorted(x for x in dates_par_hote[h] if x)
            lignes.append((h, n, H.lire(d[0])[1] if d else "—", H.lire(d[-1])[1] if d else "—"))
        S.append(f"**{len(pages)} page{'s' if len(pages) > 1 else ''}** dans l'historique, "
                 f"{len(cookies)} domaine{'s' if len(cookies) > 1 else ''} "
                 f"à cookie, {len(charges)} téléchargement{'s' if len(charges) > 1 else ''}. "
                 "Domaines les plus visités :\n")
        S.append(tableau(["domaine", "visites", "première page", "dernière page"], lignes,
                         borne=min(borne, 25), quoi="domaines", fichier="faits.jsonl"))
        # le recoupement que le skill demande : un cookie sans page d'historique
        hotes_pages = {hote(f["valeur"]) for f in pages}
        orphelins = [f for f in cookies
                     if not any(hote(f["valeur"]).lstrip(".").endswith(h) or h.endswith(hote(f["valeur"]).lstrip("."))
                                for h in hotes_pages)]
        if orphelins:
            S.append("**Cookies sans page d'historique** — une visite dont la trace "
                     "d'historique a disparu, ou qui vient d'une page tierce :\n")
            S.append(table(["domaine", "dernier accès", "id"],
                           [(f["valeur"], quand(f), f["id"]) for f in H.tri(orphelins)]))
        if charges:
            S.append("**Téléchargements** — la colonne « sur le disque » vient de la "
                     "timeline : elle dit si le fichier annoncé par le navigateur y est "
                     "vraiment, et quand il y est apparu.\n")
            S.append(table(["date", "fichier", "origine", "sur le disque", "id"],
                           [(quand(f), f["valeur"], (f.get("note") or "").replace("depuis ", ""),
                             " ; ".join(f"{quand(t)} {t['fait'].replace('fichier ', '')} ({t['id']})"
                                        for t in confirme.get(f["id"], [])) or "—",
                             f["id"]) for f in H.tri(charges)]))
        signets = [f for f in mien(par.get("navigation", [])) if f["fait"] == "marque-page enregistré"]
        recherches = [f for f in mien(par.get("navigation", [])) if f["fait"].startswith("recherche")]
        saisies = [f for f in mien(par.get("usage", [])) if f["fait"] == "saisie dans un formulaire"]
        if signets:
            S.append("**Marque-pages** — un signet est un choix délibéré, daté, et il "
                     "survit au vidage de l'historique :\n")
            S.append(table(["enregistré le", "adresse", "titre", "id"],
                           [(quand(f), f["valeur"], T(f.get("note")), f["id"])
                            for f in H.tri(signets)]))
        if recherches or saisies:
            S.append("**Ce que le compte a tapé** — recherches et saisies de formulaire : "
                     "l'intention, là où l'historique ne donne que la page atteinte.\n")
            S.append(table(["date", "quoi", "saisi", "détail", "id"],
                           [(quand(f), "recherche" if f in recherches else "formulaire",
                             f["valeur"], T(f.get("note")), f["id"])
                            for f in H.tri(recherches + saisies)]))
        if secrets:
            S.append("**Sites avec un mot de passe enregistré dans le navigateur** "
                     "(le site seul est lu) :\n")
            S.append(table(["site", "dernier usage", "id"],
                           [(f["valeur"], quand(f), f["id"]) for f in H.tri(secrets)]))
    if not comptes_nav:
        S.append("_Aucune base de navigateur dans les faits._\n")
    S.append(a_rediger("par compte : l'usage qui se dégage, daté. Un téléchargement "
                       "se recoupe avec l'apparition du fichier dans la timeline ; "
                       "citez les deux ou dites que le second manque."))

    S.append("## 8 · Les supports amovibles\n")
    if par.get("appareil"):
        S.append("Un support par ligne, recollé depuis les lignes éparses du journal. "
                 "Le numéro de série est rattaché par le **temps** — il suit son "
                 "branchement de moins d'une minute — d'où une confiance « forte » et "
                 "non « certaine » : la note donne les identifiants pour vérifier.\n")
        S.append(table(["support", "vid:pid", "branchements", "première", "dernière",
                        "monté sur", "compte", "id"],
                       [(f["valeur"], f"{f.get('vid')}:{f.get('pid')}",
                         f.get("branchements"), date_nue(f.get("premiere")),
                         date_nue(f.get("derniere")), f.get("montages"),
                         f.get("acteur"), f["id"]) for f in par["appareil"]]))
        S.append("\n**Le détail, ligne à ligne :**\n")
    S.append(table(["date", "fait", "valeur", "compte", "id"],
                   [(quand(f), f["fait"], f["valeur"], f.get("acteur"), f["id"])
                    for f in H.tri(par.get("support", []))]))
    # « role » est le nom de machine posé par l'extracteur ; le libellé en
    # français, lui, est du texte de rapport et peut être reformulé.
    montages = [f for f in par.get("support", []) if f.get("role") == "montage-amovible"]
    for m in montages:
        lignes = H.tri(confirme.get(m["id"], []))
        if not lignes:
            continue
        S.append(f"### Ce qui a été lu ou écrit sous {m['valeur']} ({m['id']})\n")
        S.append(table(["date", "quoi", "fichier", "ce que disent ses dates", "id"],
                       [(quand(f), f["fait"].replace("fichier ", "").replace(" sur un support amovible", ""),
                         f["valeur"],
                         # « ...b » est le drapeau brut de mactime ; la note du
                         # fait le dit en français. Un rapport se lit sans table
                         # de correspondance : les deux, le mot d'abord.
                         T("%s (%s)" % (f.get("note") or "—", f["genre"])
                           if f.get("genre") else (f.get("note") or "—")),
                         f["id"]) for f in lignes],
                       quoi="fichiers de ce support"))
    S.append(a_rediger("par support : branchement, numéro de série, modèle, "
                       "montage (le chemin /run/media/<compte>/ nomme le compte), "
                       "débranchement — puis ce qui a été lu ou écrit dessus "
                       "(timeline, recently-used.xbel). Un fichier « créé » (b) sous le "
                       "point de montage pendant la fenêtre du branchement est une COPIE "
                       "vers le support ; un fichier seulement « lu » (a) est une lecture. "
                       "Sans ligne de timeline : « ce qui y a été copié n'est pas établi »."))

    S.append("## 9 · Ce qui attire l'œil\n")
    S.append(table(["date", "constat", "valeur", "compte", "confiance", "id", "à vérifier"],
                   [(quand(f), f["fait"], f["valeur"], f.get("acteur"), f.get("confiance"),
                     f["id"], "…") for f in H.tri(par.get("suspect", []))]))
    persistants = [f for f in par.get("persistance", []) if not f.get("acteur")]
    if persistants:
        S.append("### Ce qui se relance seul\n")
        S.append("Tâches planifiées, unités systemd, autostart, règles udev : ce qui "
                 "repart sans qu'on le demande. Une unité posée dans `/etc` l'a été à la "
                 "main ou par un installeur — pas par le gestionnaire de paquets.\n")
        S.append(table(["quoi", "valeur", "source", "id"],
                       [(f["fait"], f["valeur"], f["source"], f["id"]) for f in persistants]))
    if par.get("recuperation"):
        S.append("### Ce qui a été récupéré de l'espace libre\n")
        S.append("photorec rend un contenu **sans nom ni date** : le type est tout ce qui "
                 "les trie. Une empreinte ou une chaîne connue s'y cherche avec "
                 "`--indicateurs`.\n")
        S.append(table(["quoi", "combien", "où", "note", "id"],
                       [(f["fait"], f["valeur"], f["source"], T(f.get("note")), f["id"])
                        for f in par["recuperation"]]))
    if par.get("chaines"):
        S.append("### Ce que les octets du disque portent encore\n")
        S.append("Les chaînes lisibles sont lues sur le **périphérique**, pas sur les "
                 "fichiers : une adresse effacée du navigateur, un chemin supprimé, une "
                 "IP retirée de toute configuration y subsistent — dans le slack, dans "
                 "le swap, dans une page libérée. C'est la pièce qui répond à « cela "
                 "a-t-il jamais été sur ce disque ? » quand le reste a été vidé.\n")
        S.append("> **Aucune de ces lignes n'est datée, ni imputable à un compte.** Une "
                 "chaîne trouvée là établit qu'elle a existé sur le volume, rien de "
                 "plus. Pour en faire un fait daté, il faut la recouper avec une pièce "
                 "qui porte une date — l'historique, la timeline, un journal.\n")
        # Le tri se fait sur un CHAMP, pas sur le libellé français : « chaînes
        # brutes du périphérique » commence lui aussi par « chaînes » et
        # atterrissait dans le tableau des nombres, le nom du volume sous la
        # colonne « combien ».
        comptages = [f for f in par["chaines"] if f.get("nature") == "compte"]
        valeurs = [f for f in par["chaines"] if f.get("occurrences")]
        bruts = [f for f in par["chaines"] if f not in comptages and f not in valeurs]
        if comptages:
            S.append(table(["quoi", "combien", "source", "id"],
                           [(f["fait"], f["valeur"], f["source"], f["id"])
                            for f in comptages]))
        if bruts:
            # Le volume n'est pas un nombre : ces lignes n'ont rien à faire
            # sous une colonne « combien ».
            S.append("\n**Les pièces brutes**, si une valeur précise doit être "
                     "cherchée — par `--indicateurs`, jamais en les ouvrant :\n")
            S.append(table(["volume", "pièce", "ce qu'elle porte", "id"],
                           [(f["valeur"], f["source"], T(f.get("note")), f["id"])
                            for f in bruts]))
        if valeurs:
            S.append("\n**Les plus fréquentes** — le nombre d'occurrences dit si une "
                     "chaîne traîne partout ou n'apparaît qu'une fois :\n")
            S.append(table(["genre", "chaîne", "volume", "occurrences", "id"],
                           [(f["fait"], f["valeur"], f.get("volume"),
                             f.get("occurrences"), f["id"]) for f in valeurs],
                           quoi="chaînes relevées"))
        S.append(a_rediger("ce que ces chaînes ajoutent, et SEULEMENT ça : une "
                           "existence sur le disque, sans date. Dites pour chacune si "
                           "une autre pièce la date — et quand aucune ne le fait, "
                           "écrivez-le plutôt que de laisser le lecteur le supposer."))
    if par.get("document"):
        S.append("### Ce que contiennent les fichiers rendus sans nom\n")
        S.append("photorec et `xfs_undelete` rendent du contenu **sans nom ni date**. "
                 "Les compter par type ne dit rien ; les ouvrir dit tout. Voici ceux "
                 "que l'extracteur a su lire, avec la première phrase qui les "
                 "identifie et ce qu'ils portent.\n")
        S.append("> **Le contenu est établi, la provenance ne l'est pas.** Un fichier "
                 "rendu par le carving n'a ni auteur, ni date, ni compte : il peut "
                 "venir d'un paquet d'installation autant que du dossier personnel. "
                 "Ouvrez la pièce avant d'attribuer quoi que ce soit.\n")
        # Les motifs viennent des faits « intérêt » posés sur la MÊME pièce, et
        # non d'une seconde recherche : deux chercheurs sur les mêmes fichiers
        # se contredisaient — l'un lit un aperçu, l'autre le fichier entier —
        # et le rapport montrait deux fois la même découverte.
        motifs = {}
        for f in par.get("interet", []):
            motifs.setdefault(f["source"], []).append(f"{f['valeur']} ({f['id']})")
        S.append(table(["pièce", "de quoi ça parle", "porte", "motifs repérés", "id"],
                       [(f["source"], T(f["valeur"]), f.get("porte"),
                         ", ".join(motifs.get(f["source"], [])) or None, f["id"])
                        for f in par["document"]],
                       quoi="documents lisibles"))
        S.append(a_rediger("les documents qui comptent, et pourquoi. Un compte rendu "
                           "de réunion n'a pas la même valeur qu'un fichier de "
                           "configuration : dites laquelle. Et rappelez pour chacun "
                           "qu'aucune date ne s'y attache."))
    if par.get("interet"):
        S.append("### Ce que l'outil a remarqué de lui-même\n")
        S.append("Une courte liste de motifs est cherchée dans **toute** la collecte à "
                 "chaque extraction — y compris dans les chaînes des disques et dans "
                 "ce que photorec a rendu, où rien d'autre dans ce rapport ne va. "
                 "Personne ne l'a demandée : elle est là pour que ce qui traîne dans "
                 "l'espace libre ne passe pas inaperçu.\n")
        S.append("> **Toutes ces lignes sont « à vérifier ».** Un secret trouvé dans "
                 "les octets n'est ni daté ni imputable, et peut venir d'un paquet "
                 "d'installation, d'un exemple de documentation ou d'un fichier de "
                 "test autant que d'un fichier du compte. **Ouvrez la pièce citée "
                 "avant d'en écrire un mot.**\n")
        S.append(table(["quoi", "où", "occurrences", "octet", "autour", "id"],
                       [(f["valeur"], f["source"], f.get("occurrences"), f.get("octet"),
                         T(f.get("contexte")), f["id"]) for f in par["interet"]],
                       quoi="motifs remarqués"))
        S.append(a_rediger("pour chaque ligne retenue : ce que la pièce contient "
                           "vraiment, une fois ouverte. Rayez le reste en disant "
                           "pourquoi — « chaîne d'exemple d'un paquet », « clé de "
                           "test ». Une ligne non vérifiée ne va pas dans le rapport."))
    if par.get("indicateur"):
        S.append("### Les indicateurs cherchés\n")
        S.append("Ce que l'analyste a demandé de chercher (`--indicateurs`), trouvé ou non :\n")
        S.append(table(["indicateur", "résultat", "où", "note", "id"],
                       [(f["valeur"], f["fait"], f["source"], T(f.get("note")), f["id"])
                        for f in par["indicateur"]]))
    S.append(a_rediger("remplissez « à vérifier » : ce qui rendrait chaque ligne "
                       "vraie ou fausse. N'affirmez pas une compromission. Retirez "
                       "ce qui est banal en le disant."))

    S.append("## 10 · Les limites\n")
    S.append(table(["limite", "valeur", "note", "id"],
                   [(f["fait"], f["valeur"], T(f.get("note")), f["id"]) for f in par.get("limite", [])]))
    reprises = []
    for f in par.get("limite", []):
        m = RE_REPRISE.search(f.get("note") or "")
        if m:
            reprises.append((f["valeur"], m.group(1), m.group(2), f["id"]))
    if reprises:
        S.append("### Demande de reprise\n")
        S.append("Pièces absentes que la collecte sait reprendre. À transmettre telle quelle "
                 "à qui a l'image ; le numéro de chaque étape se lit dans le plan :\n")
        S.append("    sudo ./tasker.sh -c exemples/collecte-linux.conf -l --set MONTAGE=… --set PERIPH=…\n"
                 "    sudo ./tasker.sh -c exemples/collecte-linux.conf --only <numéros> --set MONTAGE=… --set PERIPH=…\n")
        S.append(table(["pièce", "chemin sur le système d'origine", "étape à rejouer", "id"], reprises))
        S.append("Une pièce reprise à la main se pose dans le dossier de la collecte, sous "
                 "le nom que l'extracteur attend (`references/ou-chercher.md`), puis "
                 "l'extraction se relance.\n")
    S.append(a_rediger("pour chaque pièce manquante : le système ne l'avait pas, "
                       "ou la collecte l'a ratée ? (PREFIX_rapport.txt de la "
                       "collecte tranche). Les trous de journaux : première et "
                       "dernière date de chaque source. Ce que la mémoire vive et "
                       "le réseau auraient dit."))

    S.append("## 11 · Annexe : méthode\n")
    outil = man.get("extracteur") or {}
    # Les listes de recherche avec leur empreinte : sans elles, le rapport dit
    # par quel outil les faits ont été tirés, mais pas à quelles QUESTIONS il
    # répondait — et une réponse « ABSENT » ne veut rien dire sans la question.
    listes = man.get("listes_de_recherche") or []
    S.append(tableau(["", ""], [
        ("commande", f"`{man.get('commande')}`" if man.get("commande") else None),
        ("extracteur", outil.get("fichier")),
        ("empreinte de l'extracteur", outil.get("sha256")),
        ("listes de recherche", " ; ".join(
            f"{os.path.basename(x.get('fichier', ''))} ({str(x.get('sha256'))[:12]}…)"
            for x in listes) or "aucune — seuls les motifs de l'outil"),
        ("questions posées", man.get("questions")),
        ("empreinte de la provenance", man.get("provenance_sha256")),
        ("empreinte des faits", man.get("faits_sha256")),
        ("faits", len(faits)),
        ("pièces lues", len(man.get("pieces_lues") or {})),
    ]))
    S.append(tableau(["catégorie", "faits"], sorted((k, len(v)) for k, v in par.items())))
    S.append("### Pièces lues\n")
    S.append(table(["pièce", "sha256", "octets"],
                   [(p, v.get("sha256"), v.get("octets"))
                    for p, v in sorted((man.get("pieces_lues") or {}).items())]))
    S.append("### Table des faits cités\n")
    S.append(a_rediger("une ligne par fait cité dans le rapport : id, source, "
                       "méthode — recopiés de faits.jsonl, jamais réécrits."))

    restants = dict(LEXIQUE)
    for morceau in S:
        bas = morceau.lower()
        for t in [t for t in restants if t.lower() in bas]:
            restants.pop(t)
        if not restants:
            break
    S.append("## 12 · Lexique\n")
    S.append("Les termes techniques employés ci-dessus, pour un lecteur qui n'est pas du métier.\n")
    S.append(tableau(["terme", "ce que c'est"], [(t, d) for t, d in LEXIQUE.items() if t not in restants]))

    with open(sortie, "w", encoding="utf-8") as fh:
        fh.write("\n".join(S))
    print(f"{sortie} : {len(faits)} faits, {len(sess)} sessions, "
          f"{sum(x.startswith('> **À rédiger**') for x in S)} passages à rédiger",
          file=sys.stderr)


if __name__ == "__main__":
    main()
