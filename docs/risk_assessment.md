# Risk Assessment (M5-04)

## Principe

Le risk combine severity (M5-02), confidence (M5-01) et host criticality (M5-03) en
une evaluation unique et deterministe. Contrainte explicite validee en revue : ne pas
se limiter a severity x confidence, qui ignorerait completement la criticite de
l'hote - deux incidents avec la meme severity et la meme confidence doivent pouvoir
produire des risks differents selon la criticite de la machine concernee.

## Formule

Chaque dimension est d'abord normalisee entre 0 et 1 :

- severity_score = severity_rank / 4 (severity_rank va de 0 a 4, cf M5-02)
- confidence_score = confidence (deja entre 0 et 1, cf M5-01)
- criticality_score = (criticality_rank + 1) / 4 si connue (criticality_rank va de 0
  a 3, cf M5-03) ; si criticality = "unknown", criticality_score = 0.5 (valeur neutre,
  ni optimiste ni pessimiste - un host non repertorie ne doit ni minimiser ni
  maximiser artificiellement le risk)

risk_score = 0.35 * severity_score + 0.30 * confidence_score + 0.35 * criticality_score

Le poids de la criticite (0.35) est deliberement egal a celui de la severity (0.35),
superieur a celui de la confidence (0.30) : c'est ce qui garantit que la criticite de
l'hote peut faire basculer le niveau de risk final, pas seulement le moduler
legerement - condition necessaire pour respecter la contrainte "pas un simple produit
severity x confidence".

## Categories de risk

| risk_score | Categorie |
|---|---|
| >= 0.75 | critical |
| >= 0.55 | high |
| >= 0.35 | medium |
| < 0.35 | low |

## Priority

La priority derive directement de la categorie de risk :

| Categorie de risk | Priority |
|---|---|
| critical | P1 |
| high | P2 |
| medium | P3 |
| low | P4 |

## Exemple illustrant la contrainte (cas A vs B de M5-05)

Incident A : severity=high (rank 3), confidence=0.80, host criticality=low (rank 0)
  severity_score=0.75, confidence_score=0.80, criticality_score=0.25
  risk_score = 0.35*0.75 + 0.30*0.80 + 0.35*0.25 = 0.2625 + 0.24 + 0.0875 = 0.59
  -> categorie high, priority P2

Incident B : memes severity et confidence, host criticality=critical (rank 3)
  severity_score=0.75, confidence_score=0.80, criticality_score=1.0
  risk_score = 0.35*0.75 + 0.30*0.80 + 0.35*1.0 = 0.2625 + 0.24 + 0.35 = 0.8525
  -> categorie critical, priority P1

B est bien priorise devant A alors que seule la criticite de l'hote differe - la
formule reagit comme attendu, valide en M5-05.

## Ce que le risk ne signifie PAS

Un risk "critical" ne signifie pas "attaque confirmee". Il signifie "la combinaison
de la dangerosite de la technique, de la fiabilite des preuves et de la criticite de
la machine justifie un traitement prioritaire par l'analyste" - la decision finale
(est-ce reellement une attaque ?) reste entierement a l'analyste, coherent avec la
philosophie evidence-driven de ForensiX (M4-03).

## Limite constatee empiriquement : categorisation et incertitude

Verifie en M5-04 : severity=critical + criticality=critical avec confidence=0.20 donne
risk_score=0.76 (categorie critical, P1), tandis que la meme combinaison avec
confidence=0.90 donne risk_score=0.97 (categorie critical, P1 egalement). Le seuil de
0.75 pour "critical" ne separe pas ces deux cas malgre un ecart de confidence de 0.70.

Le score numerique brut (risk_score) reflete correctement l'incertitude (ecart de
0.21 entre les deux cas), mais la categorie discrete (critical/P1 dans les deux cas)
efface cette distinction. Consequence pour M6 : l'interface analyste devra toujours
exposer le risk_score numerique en plus de la categorie, jamais la categorie seule -
sinon l'incertitude du cas C (severity/criticalite elevees mais confidence faible)
serait invisible pour l'analyste alors qu'elle est une information cruciale.

Cette limite n'a pas ete corrigee en ajustant les poids ou les seuils, conformement a
la regle etablie en M3-01/M5-01 : ne jamais retoucher une formule documentee pour
obtenir un resultat different de celui qu'elle produit reellement.
