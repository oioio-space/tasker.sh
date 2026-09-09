#!/usr/bin/env python3
"""Prépare le BROUILLON du rapport de conformité : les tableaux, pas la prose.

    brouillon.py constats.jsonl [--faits faits.jsonl] [-o rapport.md] [--fuseau …]

Tout ce qui est tableau vient des constats, dans un ordre fixe : deux analystes
obtiennent le même brouillon. Ce qui reste à écrire est marqué « À rédiger »,
avec ce qu'il faut y dire. Le modèle rédige entre les tableaux ; il ne les
refait pas, il ne les corrige pas, il ne les complète pas de mémoire.

Les dates des constats sont en UTC quand la pièce les donne ainsi ; le
brouillon les écrit dans le fuseau du poste (fait « fuseau horaire du poste »
de faits.jsonl, ou --fuseau), y compris celles qui traînent dans une note.

Le manifeste (constats-manifeste.json, à côté du fichier de constats) donne les
règles employées et les empreintes. Sans lui, le §2 et l'annexe restent à faire.
"""
import argparse, functools, json, os, re, sys
from datetime import datetime

from controles import lire_faits as lire_jsonl

RE_ISO_UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)')

PHRASE_COMPTES = (
    "> Ce rapport désigne des **comptes** — des identités numériques. Il "
    "n'établit pas qui tenait le clavier : une collecte ne le dit jamais. Un "
    "manquement imputé à un compte n'est pas, par lui-même, imputé à une personne.")

LEXIQUE = {
    "constat": "ce que le script a observé dans une pièce, sans le juger",
    "manquement": "un constat qu'une règle écrite de la charte interdit — c'est l'analyste "
                  "qui fait ce pas, pas le script",
    "portée": "« compte » : imputable à une identité numérique ; « poste » : un réglage de la "
              "machine, imputable à personne en particulier",
    "indice": "la traduction d'une règle en quelque chose que l'on cherche — un domaine, un "
              "programme, un fichier, une commande, un réseau, un horaire",
    "cookie": "petit fichier qu'un site dépose dans le navigateur ; sa présence prouve une "
              "visite, même si l'historique a été vidé",
    "SSID": "le nom d'un réseau sans fil",
    "sudo": "commande qui exécute une action avec les droits d'un autre compte, root le plus "
            "souvent",
    "NOPASSWD": "réglage de sudo qui dispense de ressaisir son mot de passe",
    "clé privée SSH": "le secret qui ouvre une connexion distante sans mot de passe ; une phrase "
                      "de passe la protège si le fichier est volé",
    "HISTTIMEFORMAT": "réglage qui fait dater chaque commande de l'historique ; sans lui, "
                      "l'historique n'a pas de dates",
    "SELinux": "un mécanisme de protection du système ; « permissive » le laisse observer sans "
               "bloquer, « disabled » l'arrête",
    "pare-feu": "ce qui filtre les connexions réseau entrantes et sortantes du poste",
    "UTC": "le temps universel ; les dates en UTC sont converties dans le fuseau du poste",
    "sha256": "une empreinte : deux fichiers de même empreinte ont le même contenu",
}


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
                 f"`grep` sur constats.jsonl, ou `--lignes` plus grand._\n")
        lignes = lignes[:borne]
    out = ["| " + " | ".join(colonnes) + " |", "|" + "---|" * len(colonnes)]
    out += ["| " + " | ".join(cellule(x, large) for x in l) + " |" for l in lignes]
    return "\n".join(out) + "\n" + coupe


def a_rediger(quoi):
    return f"> **À rédiger** — {quoi}\n"


class Horloge:
    """Écrit une date de constat dans le fuseau du poste — et celles qui
    traînent dans une note, pour qu'un rapport ne mélange jamais deux fuseaux.
    Une date sans fuseau (dpkg.log) est déjà dans l'heure du poste : ≈."""

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
        if not h:
            return "—"
        if len(str(h)) == 10:                                   # un jour seul
            return str(h)
        try:
            d = datetime.fromisoformat(str(h).replace("Z", "+00:00"))
        except ValueError:
            return str(h)
        if d.tzinfo is None:
            return f"≈ {d.isoformat(sep=' ')}"
        if self.zone:
            d = d.astimezone(self.zone)
        return d.isoformat(sep=" ")

    def texte(self, s):
        if not s or not self.zone:
            return s
        return RE_ISO_UTC.sub(lambda m: self.lire(m.group(0)), str(s))


def qui(c):
    return c.get("acteur") or "poste"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("constats")
    ap.add_argument("--faits", help="faits.jsonl du skill forensic-linux : le fuseau du "
                                    "poste, ses limites et ses indicateurs")
    ap.add_argument("--fuseau", metavar="Europe/Paris")
    ap.add_argument("--lignes", type=int, default=300, metavar="N",
                    help="lignes au plus par tableau (défaut 300)")
    ap.add_argument("-o", "--sortie")
    args = ap.parse_args()

    constats = lire_jsonl(args.constats)
    man_chemin = os.path.splitext(args.constats)[0] + "-manifeste.json"
    man = {}
    if os.path.isfile(man_chemin):
        with open(man_chemin, encoding="utf-8") as fh:
            man = json.load(fh)
    faits = lire_jsonl(args.faits) if args.faits else []
    prefix = man.get("collecte") or "PREFIX"
    sortie = args.sortie or f"rapport-conformite-{prefix}.md"
    borne = args.lignes
    fuseau = args.fuseau or next((f["valeur"] for f in faits
                                  if f.get("fait") == "fuseau horaire du poste"), None)
    H = Horloge(fuseau)
    T = H.texte

    # une seule partition des constats, dont toutes les sections se servent
    regles = (man.get("regles") or {}).get("liste") or []
    par_regle, libres, lim_regles, conformes, lim = {}, [], [], [], []
    for c in constats:
        if c["theme"] == "conforme":
            conformes.append(c)
        elif c["theme"] == "limite":
            (lim_regles if c.get("regle") else lim).append(c)
        elif c.get("regle"):
            par_regle.setdefault(c["regle"], []).append(c)
        else:
            libres.append(c)

    def ids(liste):
        return ", ".join(c["id"] for c in liste) or "—"

    S = []
    S.append(f"# Rapport de conformité — {prefix}\n")
    S.append("_Brouillon produit par `brouillon.py` : les tableaux viennent des "
             "constats, la prose est à écrire aux endroits marqués. Retirez "
             "cette ligne une fois le rapport rédigé._\n")
    S.append(f"Les dates sont écrites dans le fuseau **{H.nom or 'des constats (non converti)'}** ; "
             "≈ marque une date lue telle quelle dans une pièce qui n'écrit pas son fuseau.\n")

    # ── 0 ──
    S.append("## En bref\n")
    S.append(a_rediger("cinq phrases pour qui ne lira que ceci : quelles règles ont été "
                       "confrontées à quel poste, ce qui est établi (compte, règle, date, "
                       "identifiants), ce qui est observé sans règle en face, ce que la "
                       "collecte ne permet pas de vérifier. Pas de jargon : le lexique en "
                       "fin de rapport est là pour le reste."))

    # ── 1 ──
    S.append("## 1 · Objet et périmètre\n")
    S.append(tableau(["", ""], [
        ("collecte", prefix),
        ("dossier analysé", man.get("chemin_analyse")),
        ("relevé des constats", man.get("releve_le")),
        ("commande", f"`{man.get('commande')}`" if man.get("commande") else None),
        ("règles employées", (man.get("regles") or {}).get("fichier")),
        ("empreinte des règles", (man.get("regles") or {}).get("sha256")),
        ("constats relevés", len(constats)),
        ("faits forensic", f"{len(faits)} ({args.faits})" if args.faits else "non fournis"),
    ]))
    S.append(PHRASE_COMPTES + "\n")
    S.append(a_rediger("qui demande le rapport, la version et la date de la charte, "
                       "la période examinée."))

    # ── 2 ──
    S.append("## 2 · Comment les règles ont été traduites en contrôles\n")
    if regles:
        S.append("Chaque règle est citée telle qu'elle est écrite, puis l'indice "
                 "retenu pour la chercher. **Le lecteur peut contester la "
                 "traduction avant les résultats** : c'est fait pour.\n")
        lignes = []
        for r in regles:
            indices = "<br>".join(
                f"`{i['type']}` : `{i['motif']}`" + (f" — {i['etiquette']}" if i.get("etiquette") else "")
                for i in r.get("indices", []))
            lignes.append((r["regle"], f"« {r['texte']} »", r.get("portee"), indices,
                           ids(par_regle.get(r["regle"], []))))
        S.append(tableau(["règle", "ce qu'elle dit", "portée", "indices cherchés", "constats"],
                         lignes, large=600))
    else:
        S.append("_Aucun fichier de règles n'a été donné à `controles.py`._\n")
    S.append(a_rediger("les règles de la charte qui n'ont PAS de bloc dans le fichier "
                       "de règles : dites pour chacune si elle est vérifiable avec "
                       "cette collecte, et par quel constat. Une règle trop générale "
                       "pour un contrôle va au §5."))

    # ── 3 ──
    S.append("## 3 · Constats rattachés à une règle\n")
    S.append("Un constat rattaché n'est pas encore un manquement : **c'est à "
             "l'analyste de le confirmer**, ligne par ligne, en relisant la "
             "source et la note du constat (ce que l'indice établit, et pas "
             "davantage). Ce qui ne tient pas est rayé, avec le motif.\n")
    for r in regles or [{"regle": k} for k in sorted(par_regle)]:
        rid = r["regle"]
        vrais = par_regle.get(rid, [])
        S.append(f"### {rid} — {r.get('titre', '')}\n")
        if not vrais:
            S.append("_Aucun constat rattaché._\n")
            continue
        S.append(tableau(["id", "compte / poste", "constat", "valeur", "date", "source"],
                         [(c["id"], qui(c), c["constat"], T(c.get("valeur")),
                           H.lire(c.get("date")), c.get("source")) for c in vrais],
                         borne=borne, quoi="constats"))
        S.append(a_rediger(f"pour {rid}, une phrase par compte : ce qui est établi, "
                           "à quelle date, par quels constats et faits (C…, F…), "
                           "et la limite de l'indice recopiée depuis la note. "
                           "Un constat de portée « poste » ne se rattache à aucun "
                           "compte."))

    # ── 4 ──
    S.append("## 4 · Observations sans règle correspondante\n")
    par_theme = {}
    for c in libres:
        par_theme.setdefault(c["theme"], []).append(c)
    for th, liste in sorted(par_theme.items()):
        S.append(f"### {th}\n")
        S.append(tableau(["id", "compte / poste", "constat", "valeur", "date", "question à la charte"],
                         [(c["id"], qui(c), c["constat"], T(c.get("valeur")), H.lire(c.get("date")),
                           c.get("question")) for c in liste], borne=borne, quoi="constats"))
    if not libres:
        S.append("_Aucune._\n")
    S.append(a_rediger("si la charte fournie couvre l'une de ces observations, "
                       "déplacez-la au §3 avec la règle en face. Sinon, laissez-la "
                       "ici : ni accusation ni silence."))

    # ── 5 ──
    S.append("## 5 · Règles non vérifiables avec cette collecte\n")
    S.append(tableau(["règle", "ce qui n'a pas pu être cherché", "id"],
                     [(c["regle"], c["constat"], c["id"]) for c in lim_regles], borne=borne))
    S.append(a_rediger("les règles de la charte qu'aucune pièce ne peut vérifier "
                       "(session verrouillée, mot de passe partagé, prêt du poste…), "
                       "et ce qu'il faudrait collecter pour y répondre."))

    # ── 6 ──
    S.append("## 6 · Ce qui est conforme\n")
    S.append(tableau(["règle", "résultat", "ce que cela ne prouve pas", "id"],
                     [(c.get("regle"), c["constat"], c.get("note"), c["id"]) for c in conformes],
                     borne=borne))
    S.append(a_rediger("les bonnes pratiques observées (clé protégée, pare-feu "
                       "actif, mots de passe expirant…) — cherchez-les dans les "
                       "constats ; un rapport qui ne relève que le négatif se "
                       "discrédite."))

    # ── 7 ──
    S.append("## 7 · Limites\n")
    S.append("### Pièces et contrôles\n")
    S.append(tableau(["id", "limite", "détail"],
                     [(c["id"], c["constat"], c.get("note")) for c in lim], borne=borne))
    if faits:
        S.append("### Limites relevées par le skill forensic-linux\n")
        S.append(tableau(["id", "limite", "valeur", "note"],
                         [(f["id"], f["fait"], f.get("valeur"), T(f.get("note")))
                          for f in faits if f.get("categorie") == "limite"], borne=borne))
        indic = [f for f in faits if f.get("categorie") == "indicateur"]
        if indic:
            S.append("### Indicateurs cherchés par le skill forensic-linux\n")
            S.append(tableau(["indicateur", "résultat", "où", "id"],
                             [(f["valeur"], f["fait"], f["source"], f["id"]) for f in indic],
                             borne=borne))
    S.append(a_rediger("les historiques non datés, les absences dont on ne sait pas "
                       "si elles viennent du système ou de la collecte (voir "
                       "PREFIX_rapport.txt de la collecte), et ce que chaque "
                       "pièce manquante empêche de conclure."))

    # ── 8 ──
    S.append("## 8 · Annexe : méthode\n")
    outil = man.get("outil") or {}
    S.append(tableau(["", ""], [
        ("outil", outil.get("fichier")),
        ("empreinte de l'outil", outil.get("sha256")),
        ("empreinte des constats", man.get("constats_sha256")),
        ("pièces lues", len(man.get("pieces_lues") or {})),
    ]))
    S.append("### Pièces lues\n")
    S.append(tableau(["pièce", "sha256", "octets"],
                     [(p, v.get("sha256"), v.get("octets"))
                      for p, v in sorted((man.get("pieces_lues") or {}).items())], borne=borne))
    S.append("### Table des constats\n")
    S.append(tableau(["id", "thème", "constat", "source", "méthode"],
                     [(c["id"], c["theme"], c["constat"], c.get("source"), c.get("methode"))
                      for c in constats], large=400, borne=borne, quoi="constats"))

    # ── 9 ──
    corps = "\n".join(S).lower()
    S.append("## 9 · Lexique\n")
    S.append("Les termes techniques employés ci-dessus, pour un lecteur qui n'est pas du métier.\n")
    S.append(tableau(["terme", "ce que c'est"],
                     [(t, d) for t, d in LEXIQUE.items() if t.lower() in corps]))

    with open(sortie, "w", encoding="utf-8") as fh:
        fh.write("\n".join(S))
    n_rediger = sum(x.startswith("> **À rédiger**") for x in S)
    print(f"{sortie} : {len(constats)} constats, {len(regles)} règles, "
          f"{n_rediger} passages à rédiger", file=sys.stderr)


if __name__ == "__main__":
    main()
