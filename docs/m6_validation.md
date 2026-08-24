# Validation end-to-end du workflow analyste (M6-05)

## Scenarios valides

### Scenario 1 : approbation telle quelle

ForensiX produit un risk assessment (severity=high, criticality=medium ->
category=medium, priority=P3). L'analyste approuve sans modification via
apply_analyst_override() avec les memes valeurs et la raison "Approved as-is
by analyst".

Verifie : override_risk_category == risk_category et override_priority ==
priority (decision finale = original), le rapport Markdown mentionne
explicitement la raison de l'approbation.

### Scenario 2 : correction avec raison documentee

Meme detection initiale (category=medium, priority=P3). L'analyste corrige
vers category=low, priority=P4 avec la raison "Confirmed authorized
administrative activity".

Verifie : les champs originaux (risk_category=medium, priority=P3) restent
strictement inchanges apres l'override - le rapport Markdown affiche les
deux : "ForensiX initial assessment" (medium/P3, immuable) ET "Analyst
decision" (low/P4, avec la raison), clairement distingues.

## Resultat

Les deux scenarios exiges par la revue technique passent sur la chaine
complete : ingestion -> detection Sigma -> correlation/risk (M5) -> override
analyste (M6-01) -> generation de rapport (M6-03) -> export Markdown (M6-04),
contre PostgreSQL reel, pas seulement en memoire.

## Point de fonctionnement decouvert pendant la validation

Un test avorte en cours d'execution (ex. coupure Docker) peut laisser des
donnees orphelines en base (event insere, mais nettoyage jamais execute).
Le nettoyage manuel doit respecter l'ordre des cles etrangeres : supprimer
RiskAssessmentRecord, puis DetectionRecord, puis EventRecord - dans cet
ordre, jamais l'inverse (EventRecord est reference par DetectionRecord via
detections_event_id_fkey). Les fixtures pytest de ce projet respectent deja
cet ordre (voir tests/test_report_export.py et autres), ce point concerne
uniquement les scripts de verification manuelle ad hoc.
