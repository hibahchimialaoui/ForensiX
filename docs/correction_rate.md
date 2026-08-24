# Taux de correction analyste (M7-05)

## Principe

compute_correction_rate() interroge directement les RiskAssessmentRecord
reels en base ayant un override_risk_category rempli (donc revus par un
analyste, via M6-01), et calcule la proportion pour laquelle la decision
finale differe de la conclusion originale de ForensiX
(override_risk_category != risk_category).

Aucune donnee fabriquee : ce chiffre reflete exactement les reviews
reellement effectuees dans la base au moment du calcul - que ce soit via
les tests automatises de M6 (M6-01, M6-05) ou via l'interface Streamlit
(M6-02) utilisee manuellement.

## Verification empirique (24/08/2026)

Sur un scenario de test avec 2 detections revues (1 approuvee telle
quelle via "Approved as-is", 1 corrigee avec la raison "False positive
confirmed") :

| Metrique | Valeur |
|---|---|
| total_reviewed | 2 |
| approved_as_is | 1 |
| corrected | 1 |
| correction_rate | 0.500 |

Le calcul correspond exactement a ce qui a ete effectivement fait
(1 correction sur 2 reviews).

## Limite

Ce taux depend entierement du volume et de la nature des reviews
effectuees jusqu'ici (essentiellement les tests automatises de M6, un
tres petit echantillon). Il ne represente pas un taux de correction
attendu dans un contexte operationnel reel avec un volume d'incidents
et un analyste different. A mesure que le systeme est utilise
davantage, ce chiffre se recalcule automatiquement sur les donnees
disponibles - c'est une mesure vivante, pas une constante figee dans ce
document.
