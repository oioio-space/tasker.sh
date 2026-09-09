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
import argparse, json, os, re, sys
from datetime import datetime, timezone

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
    H = Horloge(args.fuseau or fuseau_des_faits(faits))
    T = H.texte

    def table(colonnes, lignes, **kw):
        return tableau(colonnes, lignes, borne=borne, fichier="constats.jsonl", **kw)

    def date(c):
        return H.lire(c.get("date"))[1]

    # une seule partition des constats, dont toutes les sections se servent
    regles = (man.get("regles") or {}).get("liste") or []
    par_regle, libres, limites, conformes = {}, [], [], []
    for c in constats:
        if c["theme"] == "conforme":
            conformes.append(c)
        elif c["theme"] == "limite":
            limites.append(c)
        elif c.get("regle"):
            for rid in c.get("regles") or [c["regle"]]:
                par_regle.setdefault(rid, []).append(c)
        else:
            libres.append(c)

    def ids(liste):
        return ", ".join(c["id"] for c in liste) or "—"

    S = []
    S.append(f"# Rapport de conformité — {prefix}\n")
    S.append("_Brouillon produit par `brouillon.py` : les tableaux viennent des "
             "constats, la prose est à écrire aux endroits marqués. Retirez "
             "cette ligne une fois le rapport rédigé._\n")
    S.append(f"Les dates sont écrites dans le fuseau **{H.nom or 'UTC, faute de fuseau connu'}** ; "
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
        S.append(table(["id", "compte / poste", "constat", "valeur", "date", "source"],
                       [(c["id"], qui(c), c["constat"], T(c.get("valeur")), date(c), c.get("source"))
                        for c in vrais], quoi="constats"))
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
        S.append(table(["id", "compte / poste", "constat", "valeur", "date", "question à la charte"],
                       [(c["id"], qui(c), c["constat"], T(c.get("valeur")), date(c), c.get("question"))
                        for c in liste], quoi="constats"))
    if not libres:
        S.append("_Aucune._\n")
    S.append(a_rediger("si la charte fournie couvre l'une de ces observations, "
                       "déplacez-la au §3 avec la règle en face. Sinon, laissez-la "
                       "ici : ni accusation ni silence."))

    # ── 5 ──
    S.append("## 5 · Règles non vérifiables avec cette collecte\n")
    S.append(table(["règle", "ce qui n'a pas pu être cherché", "id"],
                   [(c["regle"], c["constat"], c["id"]) for c in limites if c.get("regle")]))
    S.append(a_rediger("les règles de la charte qu'aucune pièce ne peut vérifier "
                       "(session verrouillée, mot de passe partagé, prêt du poste…), "
                       "et ce qu'il faudrait collecter pour y répondre."))

    # ── 6 ──
    S.append("## 6 · Ce qui est conforme\n")
    S.append(table(["règle", "résultat", "ce que cela ne prouve pas", "id"],
                   [(c.get("regle"), c["constat"], c.get("note"), c["id"]) for c in conformes]))
    S.append(a_rediger("les bonnes pratiques observées (clé protégée, pare-feu "
                       "actif, mots de passe expirant…) — cherchez-les dans les "
                       "constats ; un rapport qui ne relève que le négatif se "
                       "discrédite."))

    # ── 7 ──
    S.append("## 7 · Limites\n")
    S.append("### Pièces et contrôles\n")
    S.append(table(["id", "limite", "détail"],
                   [(c["id"], c["constat"], T(c.get("note"))) for c in limites if not c.get("regle")]))
    if faits:
        S.append("### Limites relevées par le skill forensic-linux\n")
        S.append(table(["id", "limite", "valeur", "note"],
                       [(f["id"], f["fait"], f.get("valeur"), T(f.get("note")))
                        for f in faits if f.get("categorie") == "limite"]))
        indic = [f for f in faits if f.get("categorie") == "indicateur"]
        if indic:
            S.append("### Indicateurs cherchés par le skill forensic-linux\n")
            S.append(table(["indicateur", "résultat", "où", "id"],
                           [(f["valeur"], f["fait"], f["source"], f["id"]) for f in indic]))
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
    S.append(table(["pièce", "sha256", "octets"],
                   [(p, v.get("sha256"), v.get("octets"))
                    for p, v in sorted((man.get("pieces_lues") or {}).items())]))
    S.append("### Table des constats\n")
    S.append(table(["id", "thème", "constat", "source", "méthode"],
                   [(c["id"], c["theme"], c["constat"], c.get("source"), c.get("methode"))
                    for c in constats], large=400, quoi="constats"))

    # ── 9 ──
    restants = dict(LEXIQUE)
    for morceau in S:
        bas = morceau.lower()
        for t in [t for t in restants if t.lower() in bas]:
            restants.pop(t)
        if not restants:
            break
    S.append("## 9 · Lexique\n")
    S.append("Les termes techniques employés ci-dessus, pour un lecteur qui n'est pas du métier.\n")
    S.append(tableau(["terme", "ce que c'est"], [(t, d) for t, d in LEXIQUE.items() if t not in restants]))

    with open(sortie, "w", encoding="utf-8") as fh:
        fh.write("\n".join(S))
    n_rediger = sum(x.startswith("> **À rédiger**") for x in S)
    print(f"{sortie} : {len(constats)} constats, {len(regles)} règles, "
          f"{n_rediger} passages à rédiger", file=sys.stderr)


if __name__ == "__main__":
    main()
