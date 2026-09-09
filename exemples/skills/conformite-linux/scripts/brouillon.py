#!/usr/bin/env python3
"""Prépare le BROUILLON du rapport de conformité : les tableaux, pas la prose.

    brouillon.py constats.jsonl [--faits faits.jsonl] [-o rapport.md]

Tout ce qui est tableau vient des constats, dans un ordre fixe : deux analystes
obtiennent le même brouillon. Ce qui reste à écrire est marqué « À rédiger »,
avec ce qu'il faut y dire. Le modèle rédige entre les tableaux ; il ne les
refait pas, il ne les corrige pas, il ne les complète pas de mémoire.

Le manifeste (constats-manifeste.json, à côté du fichier de constats) donne les
règles employées et les empreintes. Sans lui, le §2 et l'annexe restent à faire.
"""
import argparse, json, os, sys

SANS_REGLE = ("limite", "conforme")

PHRASE_COMPTES = (
    "> Ce rapport désigne des **comptes** — des identités numériques. Il "
    "n'établit pas qui tenait le clavier : une collecte ne le dit jamais. Un "
    "manquement imputé à un compte n'est pas, par lui-même, imputé à une personne.")


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


def qui(c):
    return c.get("acteur") or "poste"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("constats")
    ap.add_argument("--faits", help="faits.jsonl du skill forensic-linux : ses "
                                    "limites vont au §7")
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

    regles = (man.get("regles") or {}).get("liste") or []
    par_regle = {}
    for c in constats:
        if c.get("regle"):
            par_regle.setdefault(c["regle"], []).append(c)
    ids = lambda liste: ", ".join(c["id"] for c in liste) or "—"    # noqa: E731

    S = []
    S.append(f"# Rapport de conformité — {prefix}\n")
    S.append("_Brouillon produit par `brouillon.py` : les tableaux viennent des "
             "constats, la prose est à écrire aux endroits marqués. Retirez "
             "cette ligne une fois le rapport rédigé._\n")

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
                       "la période examinée, le fuseau dans lequel les heures sont "
                       "écrites (celui du poste, sauf mention contraire)."))

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
            vrais = [c for c in par_regle.get(r["regle"], []) if c["theme"] not in SANS_REGLE]
            lignes.append((r["regle"], f"« {r['texte']} »", r.get("portee"), indices, ids(vrais)))
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
    for r in regles or [{"regle": k, "titre": ""} for k in sorted(par_regle)]:
        rid = r["regle"]
        vrais = [c for c in par_regle.get(rid, []) if c["theme"] not in SANS_REGLE]
        S.append(f"### {rid} — {r.get('titre', '')}\n")
        if not vrais:
            S.append("_Aucun constat rattaché._\n")
            continue
        lignes = [(c["id"], qui(c), c["constat"], c.get("valeur"), c.get("date"),
                   c.get("source")) for c in vrais]
        S.append(tableau(["id", "compte / poste", "constat", "valeur", "date", "source"], lignes))
        S.append(a_rediger(f"pour {rid}, une phrase par compte : ce qui est établi, "
                           "à quelle date, par quels constats et faits (C…, F…), "
                           "et la limite de l'indice recopiée depuis la note. "
                           "Un constat de portée « poste » ne se rattache à aucun "
                           "compte."))

    # ── 4 ──
    S.append("## 4 · Observations sans règle correspondante\n")
    libres = [c for c in constats if not c.get("regle") and c["theme"] not in SANS_REGLE]
    themes = sorted({c["theme"] for c in libres})
    for th in themes:
        S.append(f"### {th}\n")
        S.append(tableau(["id", "compte / poste", "constat", "valeur", "question à la charte"],
                         [(c["id"], qui(c), c["constat"], c.get("valeur"), c.get("question"))
                          for c in libres if c["theme"] == th]))
    if not libres:
        S.append("_Aucune._\n")
    S.append(a_rediger("si la charte fournie couvre l'une de ces observations, "
                       "déplacez-la au §3 avec la règle en face. Sinon, laissez-la "
                       "ici : ni accusation ni silence."))

    # ── 5 ──
    S.append("## 5 · Règles non vérifiables avec cette collecte\n")
    lim_regles = [c for c in constats if c.get("regle") and c["theme"] == "limite"]
    S.append(tableau(["règle", "ce qui n'a pas pu être cherché", "id"],
                     [(c["regle"], c["constat"], c["id"]) for c in lim_regles]))
    S.append(a_rediger("les règles de la charte qu'aucune pièce ne peut vérifier "
                       "(session verrouillée, mot de passe partagé, prêt du poste…), "
                       "et ce qu'il faudrait collecter pour y répondre."))

    # ── 6 ──
    S.append("## 6 · Ce qui est conforme\n")
    conformes = [c for c in constats if c["theme"] == "conforme"]
    S.append(tableau(["règle", "résultat", "ce que cela ne prouve pas", "id"],
                     [(c.get("regle"), c["constat"], c.get("note"), c["id"]) for c in conformes]))
    S.append(a_rediger("les bonnes pratiques observées (clé protégée, pare-feu "
                       "actif, mots de passe expirant…) — cherchez-les dans les "
                       "constats ; un rapport qui ne relève que le négatif se "
                       "discrédite."))

    # ── 7 ──
    S.append("## 7 · Limites\n")
    lim = [c for c in constats if not c.get("regle") and c["theme"] == "limite"]
    S.append("### Pièces et contrôles\n")
    S.append(tableau(["id", "limite", "détail"],
                     [(c["id"], c["constat"], c.get("note")) for c in lim]))
    if faits:
        S.append("### Limites relevées par le skill forensic-linux\n")
        S.append(tableau(["id", "limite", "valeur", "note"],
                         [(f["id"], f["fait"], f.get("valeur"), f.get("note"))
                          for f in faits if f.get("categorie") == "limite"]))
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
                      for p, v in sorted((man.get("pieces_lues") or {}).items())]))
    S.append("### Table des constats\n")
    S.append(tableau(["id", "thème", "constat", "source", "méthode"],
                     [(c["id"], c["theme"], c["constat"], c.get("source"), c.get("methode"))
                      for c in constats], large=400))

    with open(sortie, "w", encoding="utf-8") as fh:
        fh.write("\n".join(S))
    n_rediger = sum(x.startswith("> **À rédiger**") for x in S)
    print(f"{sortie} : {len(constats)} constats, {len(regles)} règles, "
          f"{n_rediger} passages à rédiger", file=sys.stderr)


if __name__ == "__main__":
    main()
