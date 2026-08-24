# Metriques de performance (M7-04)

## Ce que ces chiffres representent

Une reference chiffree du pipeline complet (ingestion -> detection Sigma ->
correlation) sur un volume d'evenements synthetiques, executee dans
l'environnement de developpement local (PostgreSQL Docker sur la machine
de l'utilisateur). Pas une garantie de performance en production, qui
dependrait du materiel, du volume reel de trafic, et de la charge
concurrente.

## Resultat mesure (100 evenements synthetiques, 24/08/2026)

| Etape | Temps |
|---|---|
| Ingestion (bulk insert) | 0.1095s |
| Detection Sigma (7 regles) | 0.1606s |
| Correlation (clustering) | 0.0419s |
| **Total** | **0.3120s** |

**Debit : environ 320 evenements/seconde** sur ce volume et cet environnement.

## Limites de cette mesure

- Execution unique, pas une moyenne sur plusieurs runs
- Volume relativement modeste (100 evenements), le comportement a plus
  grande echelle (milliers/millions d'evenements) n'est pas mesure ici
- Executee en local, pas dans un environnement de production dimensionne
- Les evenements synthetiques sont uniformes (memes types de process
  creation) - un trafic reel plus varie pourrait avoir un profil de
  performance different, notamment sur l'etape de detection Sigma

## Usage prevu

Ce chiffre sert de point de reference pour detecter une regression de
performance future (ex. si l'ajout d'une nouvelle regle ou d'un nouveau
facteur de correlation ralentit significativement le pipeline), pas comme
un SLA de production.
