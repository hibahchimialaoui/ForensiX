# Validation multi-scenarios M5 (M5-05)

## Note sur le scenario C

Le scenario C tel que decrit en revue ("severity critique + confidence basse +
criticite critique") n'est pas atteignable avec de vraies regles : aucune des 4
regles operationnelles (M2-02) n'a de niveau Sigma "critical" (verifie en M5-02,
toutes sont "high" ou "medium"). Meme principe d'honnetete que le scenario negatif
de M4-04 : plutot que de fabriquer une regle critique artificielle, le scenario C
utilise la regle mobsync (severity="medium", la plus proche disponible), combinee a
une confidence basse obtenue naturellement (evenement isole, sans cluster correle)
et une criticite d'hote critique.

Erreur corrigee en cours de route : la documentation initiale du scenario C
affirmait a tort "severity high" - verifie apres execution reelle, la regle mobsync
a severity="medium". Corrige immediatement plutot que laisse en l'etat.

## Resultats (verifies empiriquement le 18/08/2026, contre PostgreSQL reel)

| Scenario | Confidence | Severity | Criticality | Risk score | Categorie | Priority |
|---|---|---|---|---|---|---|
| A | 0.310 | high | low | 0.443 | medium | P3 |
| B | 0.310 | high | critical | 0.705 | high | P2 |
| C | 0.230 | medium | critical | 0.594 | high | P2 |

## Verifications

- **A vs B** : memes regle/severity/confidence, seule la criticite differe (low vs
  critical). B est bien priorise devant A (P2 vs P3) - confirme la contrainte
  validee en revue : la criticite seule peut faire basculer la priority.
- **C** : la confidence la plus basse des 3 scenarios (0.230, evenement isole sans
  cluster) traduit correctement l'incertitude sur l'analyse, meme si le risk reste
  eleve (P2) a cause de la criticite critique de l'hote - coherent avec le principe
  pose en M5-04 : le risk_score reflete l'incertitude, mais peut rester dans une
  categorie elevee si la criticite du contexte le justifie.

## Structures preparees pour M6 (non utilisees dans M5)

RiskAssessmentRecord contient 3 colonnes reservees (override_risk_category,
override_priority, override_reason), toutes verifiees vides (None) dans les 3
scenarios ci-dessus. Aucune logique de correction analyste n'est implementee dans
ce milestone - uniquement le schema, pour que M6 n'exige pas de nouvelle migration
pour ajouter cette capacite.
