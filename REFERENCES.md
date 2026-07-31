# Référentiel d'audit

Les constats produits par l'analyse s'appuient sur le guide de mise en production
d'Elastic. Chaque axe d'analyse défini dans `commands.json` porte un champ
`reference` pointant vers le chapitre correspondant, afin que chaque
recommandation du rapport soit opposable à une source officielle.

## Guide principal

Production guidance
<https://www.elastic.co/docs/deploy-manage/production-guidance>

Run Elasticsearch in production
<https://www.elastic.co/docs/deploy-manage/production-guidance/elasticsearch-in-production-environments>

## Chapitres utilisés par axe

| Axe | Chapitre |
|---|---|
| `resilience` | <https://www.elastic.co/docs/deploy-manage/production-guidance/availability-and-resilience> |
| `dimensionnement` | <https://www.elastic.co/docs/deploy-manage/production-guidance/scaling-considerations> |
| `shards` | <https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/size-shards> |
| `indexation` | <https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/indexing-speed> |
| `recherche` | <https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/search-speed> |
| `disque` | <https://www.elastic.co/docs/deploy-manage/production-guidance/optimize-performance/disk-usage> |
| `cycle_de_vie` | <https://www.elastic.co/docs/manage-data/lifecycle/index-lifecycle-management> |
| `sauvegarde` | <https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore> |
| `securite` | <https://www.elastic.co/docs/deploy-manage/security> |
| `licence` | <https://www.elastic.co/subscriptions> |

Chapitres connexes cités ponctuellement :

- Recommandations générales
  <https://www.elastic.co/docs/deploy-manage/production-guidance/general-recommendations>
- Tiers de données
  <https://www.elastic.co/docs/manage-data/lifecycle/data-tiers>
- Supervision
  <https://www.elastic.co/docs/deploy-manage/monitor>

## Limite connue

L'axe `licence` est le seul à sortir du guide de mise en production : les
commandes `license`, `xpack_info` et `xpack_usage` n'ont pas de chapitre
correspondant. Il pointe vers la page des souscriptions, qui n'a pas le même
statut de guide technique.

## Portée des versions

Ces URL décrivent la documentation Elastic unifiée, qui couvre les versions
courantes. Les stacks de test du dépôt sont en 7.17.29, 8.19.9 et 9.2.3 ; la
7.17 est en fin de vie et plusieurs recommandations du guide ne s'y appliquent
pas à l'identique. Les prompts d'axe demandent explicitement de tenir compte de
la version relevée dans `audit_infos.json`.

Arborescence vérifiée le 2026-07-31. La documentation Elastic est réorganisée
régulièrement : revalider ces liens avant toute restitution client.
