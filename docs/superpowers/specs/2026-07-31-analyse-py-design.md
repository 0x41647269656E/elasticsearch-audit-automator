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
| Volume | Artefacts envoyés intégralement tant qu'ils tiennent dans la fenêtre ; trois agrégations ciblées au-delà |
| Modèle | `claude-opus-5`, `effort: "high"` |
| Fiabilité | Repli serveur sur refus, sortie structurée, cache de prompt |
| Traitement par lot | Écarté — surcoût accepté au profit d'un rapport immédiat |
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

L'API Batches aurait divisé le coût par deux mais rejette `fallbacks` ; elle est écartée
au profit d'un rapport disponible dans la foulée de la collecte, le surcoût
étant assumé. Les dix axes partent donc en synchrone, en streaming avec
`get_final_message()` pour éviter les délais d'expiration HTTP sur les entrées
volumineuses.

## Partie 5 — Budget de fenêtre et agrégations ciblées

Envoyer tout ne tient pas à l'échelle d'un cluster client. Mesure faite sur un
cluster 8.19.9 réel, puis extrapolée à 400 index / 10 nœuds / 1600 copies de
shard / 40 000 segments : **cinq axes sur dix dépassent la fenêtre d'un million
de jetons** dès 200 champs de mapping par index.

```
disque         15,2 Mo   4 552k jetons   dépasse
recherche      13,5 Mo   4 044k jetons   dépasse
indexation     13,4 Mo   4 017k jetons   dépasse
shards          9,5 Mo   2 836k jetons   dépasse
resilience      6,7 Mo   1 994k jetons   dépasse
dimensionnement 2,4 Mo     722k jetons   ok
```

`analyse.py` mesure donc chaque axe avec `messages.count_tokens` **avant**
d'envoyer. Sous le seuil, les artefacts partent intégralement — c'est le cas des
clusters de test, et rien n'est perdu. Au-dessus, trois agrégations ciblées
s'appliquent, dans cet ordre, jusqu'à repasser sous le seuil :

| Artefact | Agrégation | Effet mesuré |
|---|---|---|
| `indices_segments` | compte et distribution de taille par shard | 7,9 Mo → ~200 Ko |
| `indices_mappings` | nombre de champs, histogramme des types, champs à risque | ~5,8 Mo → ~150 Ko |
| `cluster_state` | anomalies de routage et métadonnées, sans redupliquer les mappings | ~6,6 Mo → ~500 Ko |

Ces trois agrégats **répondent exactement à ce que demandent les prompts de
commande** — « le nombre de segments par shard, leur taille », « le nombre de
champs par index, l'état du mapping dynamique ». Ce n'est pas une troncature :
c'est la réponse à la question posée, sous une forme dense.

Toute agrégation appliquée est signalée dans le rapport, pour que le lecteur
sache ce que le modèle a vu.

## Partie 6 — Coût

Le multiplicateur d'envoi n'est pas la moyenne des couples (commande, axe) —
**1,79 non pondéré, mais 2,6 pondéré par la taille**, parce que les artefacts
les plus lourds sont précisément ceux qui appartiennent au plus d'axes :
`indices_settings` à 4 axes, `indices_segments`, `indices_mappings` et
`index_stats` à 3 chacun.

Coût extrapolé pour 400 index / 10 nœuds / 20 To, avant agrégation :

| Champs par index | Volume envoyé | Coût estimé |
|---|---|---|
| 50 | 42 Mo | 59–69 € |
| 200 | 62 Mo | 87–101 € |
| 1 000 | 169 Mo | 234–273 € |

Ni le volume de données ni le nombre de documents n'influent : ils ne changent
que des valeurs numériques dans le JSON, pas sa taille. Les facteurs réels sont
le nombre d'index, de shards, de segments et de champs de mapping.

Le cache de prompt couvre le préfixe commun (`audit_infos.json`, consignes), pas
les artefacts propres à chaque axe.

**Limites du modèle de coût** : mesuré sur une stack de test sans dépôt
d'instantanés et avec une poignée de rôles, il sous-estime les axes `sauvegarde`
et `securite`. Un cluster gardant 90 instantanés quotidiens sur 400 index
produirait un `snapshots_list` bien plus lourd que ce que la mesure suggère.

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
- Un axe dépassant la fenêtre est agrégé puis analysé, et le rapport le signale
- Un dossier d'audit antérieur au lot reste analysable
