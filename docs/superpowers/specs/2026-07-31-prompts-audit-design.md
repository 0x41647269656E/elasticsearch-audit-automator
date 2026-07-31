# Enrichissement des prompts d'audit — design

Date : 2026-07-31
Statut : validé, non implémenté

## Problème

`commands.json` porte un champ `prompt` sur chacune de ses 43 commandes. Ce
champ n'est lu par aucun code : `run_commands` (`main.py:291-293`) n'extrait que
`name`, `command` et `output_format`. Le `prompt` est un contrat écrit d'avance
pour un `analyse.py` qui n'existe pas.

Les prompts actuels sont des phrases isolées d'une ligne, par exemple
« Summarize cluster health and highlight red or yellow status causes. » Elles
décrivent une intention mais ne fournissent ni seuil, ni contexte, ni forme de
sortie. Un analyseur ne peut pas en tirer un constat exploitable.

## Décisions

| Sujet | Décision |
|---|---|
| Consommateur | Un LLM, appelé par axe d'analyse et non par commande |
| Taxonomie | Alignée sur le guide de mise en production Elastic |
| Schéma | `commands.json` passe en 1.1 |
| Langue | Tout en français, y compris les `description` existantes |
| Constat | Structuré, avec sévérité et référence |

Le regroupement par axe est le choix structurant. Analyser chaque artefact
isolément produit des faux positifs : juger un heap sans connaître le nombre de
nœuds ni le volume, ou un `number_of_replicas` à 0 sans savoir si le cluster est
en production. Les corrélations sont la valeur d'un audit.

## Schéma 1.1

```json
{
  "version": "1.1",
  "restitution": {
    "langue": "fr",
    "severites": ["CRITIQUE", "MAJEUR", "MINEUR", "INFORMATIF"],
    "champs_constat": ["constat", "valeur_relevee", "severite",
                       "impact", "remediation", "reference"]
  },
  "axes": {
    "<cle>": {
      "titre": "<intitulé lisible>",
      "reference": "<URL Elastic>",
      "prompt": "<consigne de corrélation et de seuils>"
    }
  },
  "commands": [
    {
      "name": "<inchangé>",
      "description": "<traduit en français>",
      "command": "<inchangé>",
      "axes": ["<cle>", "..."],
      "prompt": "<ce qu'il faut relever dans cet artefact>",
      "output_format": "<inchangé>"
    }
  ]
}
```

Une commande appartient à un ou plusieurs axes. C'est ce qui permet à
`indices_settings` d'alimenter à la fois `resilience` (replicas) et `indexation`
(`refresh_interval`).

## Les dix axes

Les neuf premiers correspondent à des chapitres réels du guide Elastic, dont
l'arborescence a été vérifiée le 2026-07-31. Les URL sont consignées dans
`REFERENCES.md` à la racine.

| Clé | Titre |
|---|---|
| `resilience` | Conception pour la résilience |
| `dimensionnement` | Dimensionnement et montée en charge |
| `shards` | Dimensionnement des shards |
| `indexation` | Performance d'indexation |
| `recherche` | Performance de recherche |
| `disque` | Utilisation disque |
| `cycle_de_vie` | Cycle de vie et tiers de données |
| `sauvegarde` | Sauvegarde et restauration |
| `securite` | Sécurisation du cluster |
| `licence` | Licence et couverture fonctionnelle |

`licence` est assumé hors référentiel : `license`, `xpack_info` et `xpack_usage`
n'ont pas de chapitre dans le guide de mise en production. L'écart est isolé
dans un axe dédié plutôt que dissimulé dans un autre.

## Deux niveaux de prompt

Les deux niveaux ont des rôles disjoints, et c'est ce qui évite l'analyse en
silo.

Le **prompt de commande** dit quoi extraire d'un artefact précis : les champs
saillants, les valeurs à relever chiffrées. Il ne conclut pas et n'attribue pas
de sévérité.

Le **prompt d'axe** dit comment corréler ces relevés, quels seuils appliquer et
comment pondérer par la typologie. C'est lui qui produit les constats.

Exemple : `nodes_jvm_info` relève le heap, `cluster_stats` le volume indexé,
`nodes_infos` le nombre de nœuds. Aucun des trois ne conclut. L'axe
`dimensionnement` juge la cohérence de l'ensemble.

## Sévérité pondérée par la typologie

`audit_infos.json` porte `cluster_typology`, parmi `PRODUCTION`, `PREPROD`,
`RECETTE`, `DEV` et `AUTRE`. Le même relevé n'a pas la même gravité selon le
contexte, et les prompts d'axe imposent cette pondération :

```
number_of_replicas = 0    PRODUCTION -> CRITIQUE
                          PREPROD    -> MAJEUR
                          DEV        -> INFORMATIF
```

## Les commandes en échec sont un signal

L'analyseur reçoit `commands_failed` et le contenu de `errors.log`, et chaque
prompt d'axe lui impose de déclarer les angles morts.

Le cas est concret et mesuré : avec `audit_policy_7_client.json` sur un cluster
7.17, sept commandes reviennent en 403, dont les quatre commandes `security_*`.
Sans cette consigne, l'axe `securite` conclurait à l'absence de problème faute
de données. Il doit écrire « rôles non évalués, privilèges insuffisants ».

De même, `tls_report.json` porte un champ `chain_source`. Quand il vaut
`leaf-only`, l'axe `securite` doit signaler que la chaîne n'a pas pu être lue au
lieu de conclure sur la seule feuille.

## Contexte fourni au LLM par axe

- `audit_infos.json` : typologie, version, nœuds, ressources
- les artefacts des commandes rattachées à l'axe
- les échecs de ces commandes, avec leur message d'erreur
- `tls_report.json` pour l'axe `securite`

## Impact sur le code

`load_commands` (`main.py:194`) rejette toute version différente de `"1.0"`. Il
doit accepter `1.0` et `1.1`, avec un test couvrant les deux et le rejet d'une
version inconnue. C'est le seul changement de `main.py` induit par ce lot.

## Périmètre

Dans le lot :

- `commands.json` en 1.1 : bloc `axes`, champ `axes` par commande
- les dix prompts d'axe
- les 43 prompts de commande retravaillés
- les 43 `description` traduites en français
- `REFERENCES.md` à la racine
- desserrage de la version dans `main.py`, avec test

Hors lot :

- `analyse.py`. Écrire le consommateur — appels LLM, agrégation, rendu du
  rapport — est un chantier distinct qui mérite son propre cadrage. Ce lot lui
  donne une cible précise au lieu d'une page blanche.

## Critères de réussite

- `commands.json` parse, 43 commandes, aucun chemin dupliqué
- chaque commande porte au moins un axe, chaque axe porte au moins une commande
- chaque axe a une `reference` résolvable, identique à `REFERENCES.md`
- `main.py` accepte 1.0 et 1.1, rejette le reste ; suite de tests au vert
- un audit réel sur les stacks 7.17, 8.19.9 et 9.2.3 produit le même nombre de
  commandes exécutées qu'avant le changement
