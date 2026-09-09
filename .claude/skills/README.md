# Skills d'analyse

Des skills au format **Agent Skills** (`SKILL.md`), lus tels quels par Claude
Code et par Crush. Ils analysent une collecte produite par
`exemples/collecte-linux.conf` ; ils ne la modifient jamais.

| skill | ce qu'il fait |
|---|---|
| `forensic-linux/` | rapport forensique : identité et installation de la machine, chronologie de vie attribuée aux comptes, réseau, domaine, navigation, supports amovibles, éléments suspects |

## Poser les skills

Dans le projet où l'on analyse — ils sont trouvés depuis `.claude/skills/`,
`.crush/skills/` ou `.agents/skills/` :

    cp -r .claude/skills/forensic-linux /chemin/du/projet/.crush/skills/

Ou une fois pour toutes, pour Crush :

    mkdir -p ~/.config/crush/skills
    cp -r .claude/skills/forensic-linux ~/.config/crush/skills/

## Ce qu'il faut installer

`python3` et sa bibliothèque standard. Rien d'autre : pas de pip, pas de MCP.
Le module `sqlite3` de la bibliothèque standard lit les historiques de
navigateur.

## S'en servir

    /forensic-linux

puis donner le dossier de collecte — celui qui s'appelle `PREFIX/` et contient
`SYSTEME/`, `COMPTES/`, `TIMELINE/`… Le skill extrait d'abord les faits, puis
rédige le rapport.

L'extraction seule, sans passer par le modèle :

    python3 forensic-linux/scripts/extraire.py <dossier PREFIX/> -o faits.jsonl
