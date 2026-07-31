# analyse.py — design

Date : 2026-07-31
Statut : validé, non implémenté
Précédé par : `2026-07-31-prompts-audit-design.md` (commands.json 1.1, dix axes)

## Problème

La collecte fonctionne : `main.py` produit un dossier d'audit de 43 artefacts,
et `commands.json` 1.1 décrit dix axes d'analyse avec leurs prompts et leurs
références Elastic. Rien ne lit ces prompts. Le projet s'arrête à la collecte
alors que sa finalité est un compte-rendu d'audit assorti de constats et
d'actions de remédiation.

`analyse.py` est le consommateur manquant. Il produit un rapport Markdown
mêlant relevés bruts et analyses.

## Décisions

| Sujet | Décision |
|---|---|
| Découpage des appels | Un appel LLM par axe, pas par commande |
| Plan du rapport | Par axe ; extrait répété, artefact complet une seule fois en annexe |
| Données brutes | Extraits cités dans le corps, artefacts en annexe |
| Métadonnées | En-tête `_audit` dans les `.json`, sidecar `.meta.json` pour le texte |
| Volume | Artefacts envoyés intégralement (fenêtre 1M d'Opus 5) |
| Modèle | `claude-opus-5`, `effort: "high"` |
| Fiabilité | Repli serveur sur refus, sortie structurée, cache de prompt |
| Traitement par lot | Optionnel, via `--batch` |
| Langue | Français |

## Partie 1 — Extension de la collecte

Deux des quatre éléments exigés par bloc de rapport ne sont pas collectés
aujourd'hui : `save_output` n'écrit que le contenu, et `audit_infos.json` ne
porte qu'un horodatage global pour tout l'audit.

`main.py` doit capturer :

- **le nœud contacté**, une fois, via `GET /` qui renvoie `name` — l'appel
  existe déjà dans `detect_cluster_name` en repli, il suffit d'en conserver le
  champ ;
- **par commande** : horodatage de début, durée, code HTTP.

Format des artefacts :

```
cluster_health.json
{
  "_audit": {
    "node": "es01",
    "at": "2026-07-31T19:01:23.412Z",
    "command": "GET /_cluster/health",
    "status": 200,
    "duration_ms": 42
  },
  "_data": { <réponse Elasticsearch inchangée> }
}

shards_list.txt        <- texte pur, non modifié
shards_list.meta.json  <- { "node", "at", "command", "status", "duration_ms" }
```

Conséquence assumée : les `.json` ne sont plus la réponse Elasticsearch brute.
Tout outil tiers qui relit ces fichiers doit descendre dans `_data`.

## Partie 2 — Structure du rapport

```
# Audit — <cluster> — <typologie> — <date>

## Synthèse
   tableau des sévérités par axe, total des constats, angles morts

## Axe 1 — Conception pour la résilience
   référence : <URL Elastic>

   ### indices_settings
       nœud      : es01
       horodatage: 2026-07-31T19:01:23.412Z
       commande  : GET /_settings
       extrait   : <ce qui concerne CET axe>        → annexe A.14

   ### shards_list
       <même forme>

   **Constats**
       constat · valeur relevée · sévérité · impact · remédiation · référence

   **Angles morts**
       commandes échouées et ce qui n'a pas pu être évalué

## Axes 2 à 10
## Annexe A — artefacts complets
```

Un artefact mobilisé par plusieurs axes réapparaît sous chacun, mais avec
l'extrait propre à cet axe : `number_of_replicas` sous Résilience,
`refresh_interval` sous Indexation. Une seule copie intégrale, en annexe.

**Seuil d'annexe** : les artefacts de moins de 50 Ko sont inclus intégralement ;
au-delà, l'annexe renvoie au fichier du dossier d'audit, qui se trouve à côté du
rapport. La traçabilité est conservée sans produire un Markdown de plusieurs Mo.

## Partie 3 — Architecture de analyse.py

Quatre responsabilités, séparables et testables isolément :

| Unité | Rôle | Dépendances |
|---|---|---|
| `chargement` | Lire le dossier d'audit, reconstituer artefacts + métadonnées | système de fichiers |
| `regroupement` | Constituer le contexte de chaque axe depuis commands.json | commands.json |
| `analyse` | Appeler le modèle, valider les constats | API Anthropic |
| `rendu` | Produire le Markdown | aucune |

Le rendu ne dépend ni du réseau ni de l'API : il se teste avec des constats
fabriqués, sans appel.

### Contexte transmis par axe

- `audit_infos.json` : typologie, version, nœuds, ressources — **stable entre
  les dix appels, donc placé en tête pour le cache de prompt**
- la consigne globale de `restitution` et le prompt de l'axe
- les artefacts des commandes rattachées à l'axe, avec leurs métadonnées
- les échecs de ces commandes, avec leur message d'erreur
- `tls_report.json` pour l'axe `securite`

### Schéma de sortie

```python
class Constat(BaseModel):
    constat: str
    valeur_relevee: str
    severite: Literal["CRITIQUE", "MAJEUR", "MINEUR", "INFORMATIF"]
    impact: str
    remediation: str
    reference: str
    extraits: list[Extrait]        # commande + fragment cité

class ResultatAxe(BaseModel):
    constats: list[Constat]
    angles_morts: list[str]
```

Les extraits cités sont **revérifiés contre l'artefact source** après réception :
un fragment introuvable est signalé dans le rapport plutôt que présenté comme
une preuve. Un LLM peut recopier de travers ; un audit ne peut pas se le
permettre.

## Partie 4 — Appels API

Modèle `claude-opus-5`, `output_config={"effort": "high"}`. La pensée adaptative
est active par défaut sur ce modèle — le paramètre `thinking` est laissé
implicite. `temperature`, `top_p` et `budget_tokens` ne sont pas acceptés.

**Sortie structurée et repli serveur ensemble.** `messages.parse()` vit sur
l'espace non-beta, alors que `fallbacks` exige `client.beta.messages`. On passe
donc par `client.beta.messages.create` avec
`output_config={"format": {"type": "json_schema", "schema": ...}}`, et la
validation Pydantic est faite côté client sur le JSON retourné.

**Refus.** L'axe `securite` transmet rôles, comptes et métadonnées de clés
d'API ; les classificateurs cyber d'Opus 5 peuvent décliner légitimement. Le
code teste `stop_reason == "refusal"` **avant** de lire `content`, et active
`fallbacks="default"` avec le beta `server-side-fallback-2026-07-01`.

**Contrainte du mode par lot** : `fallbacks` est rejeté par l'API Batches. En
mode `--batch`, un refus revient tel quel ; l'axe concerné est alors rejoué en
synchrone avec repli, et à défaut signalé comme non évalué dans le rapport.

## Partie 5 — Mode par lot

`python analyse.py <dossier> --batch` envoie les dix axes en une soumission,
puis :

- affiche un état de réception **toutes les dix minutes** (axes reçus / attendus)
- à réception complète, affiche le temps total écoulé
- écrit le rapport

Sans le drapeau, les dix axes partent en synchrone, en streaming avec
`get_final_message()` pour éviter les délais d'expiration HTTP sur les entrées
volumineuses.

`main.py` relaie le drapeau : `prompt_analysis` ne transmet aujourd'hui que le
chemin du dossier, ce qui rendrait `--batch` inatteignable depuis un audit
complet.

## Partie 6 — Coût

Les 43 commandes forment **77 couples (commande, axe)** : chaque artefact part
en moyenne **1,79 fois** à travers les dix appels. Les plus dupliqués sont
`indices_settings` et `cluster_settings_with_defaults` (4 axes), puis
`nodes_settings`, `nodes_hot_threads`, `indices_segments` et `indices_mappings`
(3 axes) — ce dernier étant aussi l'un des plus volumineux.

Le cache de prompt ne compense pas cette duplication : il couvre le préfixe
commun (`audit_infos.json`, consignes), pas les artefacts propres à chaque axe.
C'est la justification du mode par lot, à moitié tarif.

Le volume réel est mesuré avec `messages.count_tokens` avant le premier appel
facturé, plutôt qu'estimé.

## Partie 7 — Comportements

**Clé API** : lue depuis `.env` (`ANTHROPIC_API_KEY`). Si absente, un profil
`ant auth` est vérifié avant toute demande à l'utilisateur — le SDK le résout
seul.

**Échec d'un axe** : n'interrompt pas les autres. L'axe figure dans le rapport
avec son erreur, et la synthèse le compte comme non évalué.

**Audit antérieur à ce lot** : un dossier sans les nouvelles métadonnées reste
analysable. Le rapport affiche alors l'horodatage global et le nom du cluster à
la place du nœud, avec une mention explicite.

**Relance** : `rapport.md` est écrit dans le dossier d'audit et écrasé.

## Hors périmètre

- Toute modification de `commands.json` ou des prompts : le contrat est figé par
  la spec précédente.
- Un moteur autre qu'Anthropic.
- L'envoi ou l'archivage du rapport.

## Critères de réussite

- Un audit collecté puis analysé produit un `rapport.md` dont chaque constat
  porte les six champs et une référence Elastic résolvable
- Chaque extrait cité est retrouvé dans l'artefact source, ou signalé comme
  invérifiable
- Un axe dont toutes les commandes ont échoué déclare son angle mort au lieu de
  conclure au vert
- Le module de rendu se teste sans appel réseau
- `--batch` et le mode synchrone produisent le même rapport
- Un dossier d'audit antérieur au lot reste analysable
