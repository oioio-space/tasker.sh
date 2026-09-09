#!/usr/bin/env python3
"""Prépare le BROUILLON du rapport forensique : les tableaux, pas la prose.

    brouillon.py faits.jsonl [-o rapport.md] [--fuseau Europe/Paris] [--chronologie 400]

Tout ce qui est tableau vient des faits, dans un ordre fixe : deux analystes
obtiennent le même brouillon. Ce qui reste à écrire est marqué « À rédiger »,
avec ce qu'il faut y dire. Le modèle rédige entre les tableaux ; il ne les
refait pas, il ne les corrige pas, il ne les complète pas de mémoire.

Les dates sont écrites dans le fuseau du poste (fait « fuseau horaire du
poste »), sauf --fuseau. Une date sans fuseau dans les faits — une ligne
syslog, un journal d'installation — est déjà dans l'heure du poste : elle est
recopiée telle quelle, et marquée d'un ≈ pour le dire.
"""
import argparse, json, os, re, sys
from datetime import datetime

# Ce qui entre dans la chronologie : ce qui éclaire la vie de la machine. La
# navigation a sa section ; la timeline du système de fichiers est trop
# volumineuse pour un tableau et se lit à part.
CHRONOLOGIE = ("evenement", "support", "telechargement", "paquet", "suspect",
               "persistance", "usage")


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
    if v is None:
        return "—"
    t = str(v).replace("|", "\\|").replace("\n", " ")
    return t if len(t) <= large else t[:large - 1] + "…"


def tableau(colonnes, lignes, large=200):
    if not lignes:
        return "_aucune ligne_\n"
    out = ["| " + " | ".join(colonnes) + " |", "|" + "---|" * len(colonnes)]
    out += ["| " + " | ".join(cellule(x, large) for x in l) + " |" for l in lignes]
    return "\n".join(out) + "\n"


def a_rediger(quoi):
    return f"> **À rédiger** — {quoi}\n"


class Horloge:
    """Lit un horodatage de fait et le rend dans le fuseau choisi."""

    def __init__(self, nom):
        self.nom, self.zone = nom, None
        if nom:
            try:
                from zoneinfo import ZoneInfo
                self.zone = ZoneInfo(nom)
            except Exception:                                    # noqa: BLE001
                print(f"  ! fuseau « {nom} » inconnu : dates laissées telles quelles",
                      file=sys.stderr)

    def lire(self, h):
        """→ (datetime ou None, texte à afficher)."""
        if not h:
            return None, "—"
        try:
            d = datetime.fromisoformat(str(h).replace("Z", "+00:00"))
        except ValueError:
            return None, str(h)
        if d.tzinfo is None:
            return d, f"≈ {d.isoformat(sep=' ')}"
        if self.zone:
            d = d.astimezone(self.zone)
        return d, d.isoformat(sep=" ")

    def cle(self, h):
        d, _ = self.lire(h)
        return d.replace(tzinfo=None) if d else datetime.max


def hote(url):
    m = re.match(r'^[a-z]+://([^/:]+)', url or "")
    return m.group(1).lower() if m else (url or "").lower().lstrip(".")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("faits")
    ap.add_argument("-o", "--sortie")
    ap.add_argument("--fuseau", metavar="Europe/Paris")
    ap.add_argument("--chronologie", type=int, default=400, metavar="N",
                    help="lignes retenues dans la chronologie (défaut 400) ; au-delà, "
                         "le brouillon dit combien manquent et comment les lire")
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
    valeur = lambda quoi: next((f["valeur"] for f in par.get("machine", [])   # noqa: E731
                                if f["fait"] == quoi), None)
    horloge = Horloge(args.fuseau or valeur("fuseau horaire du poste"))
    quand = lambda f: horloge.lire(f.get("horodatage"))[1]                  # noqa: E731
    tri = lambda liste: sorted(liste, key=lambda f: (horloge.cle(f.get("horodatage")), f["id"]))  # noqa: E731

    S = [f"# Rapport forensique — {prefix}\n",
         "_Brouillon produit par `brouillon.py` : les tableaux viennent des faits, "
         "la prose est à écrire aux endroits marqués. Retirez cette ligne une fois "
         "le rapport rédigé._\n",
         f"Les dates sont écrites dans le fuseau **{horloge.nom or 'des faits (non converti)'}**. "
         "Une date précédée de ≈ vient d'une pièce qui n'écrit pas son fuseau — "
         "une ligne syslog, un journal d'installation — et se lit dans l'heure du "
         "poste, avec l'année déduite quand le fait le dit.\n",
         "> Ce rapport désigne des **comptes** — des identités numériques. Il "
         "n'établit pas qui tenait le clavier : une collecte ne le dit jamais.\n"]

    # ── 1 ──
    S.append("## 1 · La machine\n")
    S.append(tableau(["", "", "id", "source"],
                     [(f["fait"], f["valeur"], f["id"], f["source"])
                      for f in par.get("machine", [])]))
    S.append(a_rediger("deux phrases : ce qu'est cette machine, depuis quand elle "
                       "existe, quand elle a servi pour la dernière fois. Signalez "
                       "une horloge matérielle en heure locale si le fait le dit."))

    # ── 2 ──
    S.append("## 2 · Les comptes\n")
    sessions = {}
    for f in par.get("evenement", []):
        if "ouverture de session" in f["fait"] and f.get("acteur") and f.get("horodatage"):
            sessions.setdefault(f["acteur"], []).append(f)
    lignes = []
    for f in par.get("compte", []):
        if "(nombre)" in f["fait"]:
            continue
        s = tri(sessions.get(f["valeur"], []))
        lignes.append((f["valeur"], f["fait"], len(s),
                       quand(s[0]) if s else "—", quand(s[-1]) if s else "—", f["id"]))
    for nom in sorted(set(sessions) - {l[0] for l in lignes}):
        s = tri(sessions[nom])
        lignes.append((nom, "a ouvert des sessions sans figurer dans passwd",
                       len(s), quand(s[0]), quand(s[-1]), s[0]["id"]))
    S.append(tableau(["compte", "nature", "sessions", "première", "dernière", "id"], lignes))
    S.append(a_rediger("ce qui distingue un compte qui a servi d'un compte qui "
                       "existe. Un compte sans session n'est pas un compte inutilisé "
                       "si wtmp a été tourné : voir les limites."))

    # ── 3 ──
    S.append("## 3 · Le domaine\n")
    S.append(tableau(["", "", "id", "source"],
                     [(f["fait"], f["valeur"], f["id"], f["source"]) for f in par.get("domaine", [])]))
    S.append(a_rediger("l'appartenance au domaine est-elle prouvée (keytab, cache "
                       "sss) ou seulement configurée ?"))

    # ── 4 ──
    S.append("## 4 · Le réseau\n")
    S.append(tableau(["", "valeur", "compte", "date", "id"],
                     [(f["fait"], f["valeur"], f.get("acteur"), quand(f), f["id"])
                      for f in par.get("reseau", [])]))
    S.append(a_rediger("une phrase : où cette machine vivait (réseau, DNS, "
                       "passerelle), et si elle a connu d'autres réseaux."))

    # ── 5 ──
    S.append("## 5 · La chronologie de la machine\n")
    chrono = tri([f for f in faits if f.get("categorie") in CHRONOLOGIE and f.get("horodatage")])
    total = len(chrono)
    if total > args.chronologie:
        S.append(f"**{total} faits datés ; les {args.chronologie} plus récents sont ici.** "
                 f"Les {total - args.chronologie} plus anciens se lisent avec "
                 "`grep '\"categorie\": \"evenement\"' faits.jsonl` et les autres "
                 "catégories, ou avec `--chronologie` plus grand.\n")
        chrono = chrono[-args.chronologie:]
    S.append(tableau(["date", "compte", "catégorie", "fait", "valeur", "id", "source"],
                     [(quand(f), f.get("acteur"), f["categorie"], f["fait"], f["valeur"],
                       f["id"], f["source"]) for f in chrono]))
    S.append(a_rediger("gardez les lignes qui éclairent la vie de la machine, "
                       "retirez le bruit (répétitions de cron, sudo de maintenance) "
                       "en disant ce que vous retirez. Ajoutez une colonne "
                       "« confiance » quand le fait n'est pas « certaine »."))

    # ── 6 ──
    S.append("## 6 · La navigation et les téléchargements\n")
    nav = par.get("navigation", [])
    par_compte = {}
    for f in nav + par.get("telechargement", []) + \
            [f for f in par.get("usage", []) if "navigateur" in f["fait"]]:
        par_compte.setdefault(f.get("acteur") or "?", []).append(f)
    for compte in sorted(par_compte):
        liste = par_compte[compte]
        S.append(f"### {compte}\n")
        pages = [f for f in liste if f["fait"] == "page visitée"]
        cookies = [f for f in liste if f["fait"] == "domaine ayant posé un cookie"]
        charges = [f for f in liste if f["categorie"] == "telechargement"]
        secrets = [f for f in liste if "mot de passe" in f["fait"]]
        # les domaines les plus visités : la somme des visites de leurs pages
        visites = {}
        for f in pages:
            note = f.get("note") or ""
            m = re.match(r'(\d+) visite', note)
            premiere = re.search(r'la première le (\S+)', note)
            h = hote(f["valeur"])
            n, dates = visites.get(h, (0, []))
            visites[h] = (n + (int(m.group(1)) if m else 1),
                          dates + [f.get("horodatage")] + ([premiere.group(1)] if premiere else []))
        lignes = []
        for h, (n, dates) in sorted(visites.items(), key=lambda x: (-x[1][0], x[0]))[:25]:
            d = sorted(x for x in dates if x)
            lignes.append((h, n, horloge.lire(d[0])[1] if d else "—",
                           horloge.lire(d[-1])[1] if d else "—"))
        S.append(f"**{len(pages)} pages** dans l'historique, {len(cookies)} domaines "
                 f"à cookie, {len(charges)} téléchargements. Domaines les plus visités :\n")
        S.append(tableau(["domaine", "visites", "première page", "dernière page"], lignes))
        # le recoupement que le skill demande : un cookie sans page d'historique
        hotes_pages = {hote(f["valeur"]) for f in pages}
        orphelins = [f for f in cookies
                     if not any(hote(f["valeur"]).lstrip(".") in h or h in hote(f["valeur"]).lstrip(".")
                                for h in hotes_pages)]
        if orphelins:
            S.append("**Cookies sans page d'historique** — une visite dont la trace "
                     "d'historique a disparu, ou qui vient d'une page tierce :\n")
            S.append(tableau(["domaine", "dernier accès", "id"],
                             [(f["valeur"], quand(f), f["id"]) for f in tri(orphelins)]))
        if charges:
            S.append("**Téléchargements** :\n")
            S.append(tableau(["date", "fichier", "origine", "id"],
                             [(quand(f), f["valeur"], (f.get("note") or "").replace("depuis ", ""),
                               f["id"]) for f in tri(charges)]))
        if secrets:
            S.append("**Sites avec un mot de passe enregistré dans le navigateur** "
                     "(le site seul est lu) :\n")
            S.append(tableau(["site", "dernier usage", "id"],
                             [(f["valeur"], quand(f), f["id"]) for f in tri(secrets)]))
    if not par_compte:
        S.append("_Aucune base de navigateur dans les faits._\n")
    S.append(a_rediger("par compte : l'usage qui se dégage, daté. Un téléchargement "
                       "se recoupe avec l'apparition du fichier dans la timeline ; "
                       "citez les deux ou dites que le second manque."))

    # ── 7 ──
    S.append("## 7 · Les supports amovibles\n")
    S.append(tableau(["date", "fait", "valeur", "compte", "id"],
                     [(quand(f), f["fait"], f["valeur"], f.get("acteur"), f["id"])
                      for f in tri(par.get("support", []))]))
    S.append(a_rediger("par support : branchement, numéro de série, modèle, "
                       "montage (le chemin /run/media/<compte>/ nomme le compte), "
                       "débranchement — puis ce qui a été lu ou écrit dessus "
                       "(timeline, recently-used.xbel). Sans cela : « ce qui y a "
                       "été copié n'est pas établi »."))

    # ── 8 ──
    S.append("## 8 · Ce qui attire l'œil\n")
    S.append(tableau(["date", "constat", "valeur", "compte", "confiance", "id", "à vérifier"],
                     [(quand(f), f["fait"], f["valeur"], f.get("acteur"), f.get("confiance"),
                       f["id"], "…") for f in tri(par.get("suspect", []))]))
    S.append(a_rediger("remplissez « à vérifier » : ce qui rendrait chaque ligne "
                       "vraie ou fausse. N'affirmez pas une compromission. Retirez "
                       "ce qui est banal en le disant."))

    # ── 9 ──
    S.append("## 9 · Les limites\n")
    S.append(tableau(["limite", "valeur", "note", "id"],
                     [(f["fait"], f["valeur"], f.get("note"), f["id"])
                      for f in par.get("limite", [])]))
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
    par_cat = sorted((k, len(v)) for k, v in par.items())
    S.append(tableau(["catégorie", "faits"], par_cat))
    S.append("### Pièces lues\n")
    S.append(tableau(["pièce", "sha256", "octets"],
                     [(p, v.get("sha256"), v.get("octets"))
                      for p, v in sorted((man.get("pieces_lues") or {}).items())]))
    S.append("### Table des faits cités\n")
    S.append(a_rediger("une ligne par fait cité dans le rapport : id, source, "
                       "méthode — recopiés de faits.jsonl, jamais réécrits."))

    with open(sortie, "w", encoding="utf-8") as fh:
        fh.write("\n".join(S))
    print(f"{sortie} : {len(faits)} faits, {len(chrono)} lignes de chronologie, "
          f"{sum(x.startswith('> **À rédiger**') for x in S)} passages à rédiger",
          file=sys.stderr)


if __name__ == "__main__":
    main()
