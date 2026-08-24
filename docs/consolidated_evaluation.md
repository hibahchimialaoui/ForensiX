# Evaluation consolidee finale (M7-03)

## Ce que ce document est

Une consolidation des deux baselines existantes - M2-05 (detection Sigma) et
M3-05 (correlation multi-scenarios) - dans un rapport unique. Ce n'est pas
une nouvelle mesure : run_consolidated_evaluation() re-execute exactement
les memes jeux de test que M2-05/M3-05 et verifie qu'aucune regression n'a
ete introduite depuis.

## Ce que ce document n'est PAS

Une evaluation representative de la performance de ForensiX en production.
Les deux baselines utilisent des jeux de test construits a la main (M2-05 :
4 evenements positifs + 4 evenements benins ; M3-05 : 3 scenarios de
clustering), pas un volume ou une diversite de trafic representatifs d'un
environnement reel. Cette limite a ete posee des M2-05 et n'est pas
reevaluee ici - elle est simplement rappelee pour eviter toute
interpretation abusive de ces chiffres.

## Resultats consolides (verifies empiriquement le 24/08/2026)

### Detection Sigma (M2-05) - 4 regles pleinement operationnelles

| Regle | TP | FP | FN |
|---|---|---|---|
| PowerShell download pattern | 1 | 0 | 0 |
| Sync Center suspicious connection | 1 | 0 | 0 |
| Startup folder persistence | 1 | 0 | 0 |
| Suspicious execution path | 1 | 0 | 0 |

Aucune regression par rapport aux resultats originaux de M2-05.

### Correlation multi-clusters (M3-05)

| Scenario | Clusters obtenus | Clusters attendus |
|---|---|---|
| A (chaine unique) | 1 | 1 |
| B (deux incidents independants) | 2 | 2 |
| C (chaine + evenement isole) | 2 | 2 |

Aucune regression par rapport aux resultats originaux de M3-05.

## Conclusion

Les deux moteurs (detection et correlation) restent coherents avec leur
specification a la date de cette consolidation. Ces chiffres valident la
correction logique du systeme sur les jeux de test qui l'accompagnent,
pas une garantie de performance sur un environnement de production reel.
