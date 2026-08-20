# Confidence Model (M5-01)

## Principe

La confidence mesure a quel point les preuves disponibles soutiennent fortement une
detection donnee. Elle combine 3 facteurs, chacun normalise entre 0 et 1, combines par
une moyenne ponderee - meme discipline que le score de correlation (M3-01) : la
formule est ecrite AVANT implementation pour eviter tout ajustement des poids en
fonction d'un resultat souhaite.

**Avertissement (a reprendre tel quel dans le README) : confidence est un score
analytique base sur les preuves disponibles, PAS une probabilite statistique calibree
de justesse.** Une confidence de 0.90 signifie "les elements disponibles soutiennent
fortement cette interpretation", pas "90% de chances que ForensiX ait raison dans le
monde reel" - notre dataset ne permet aucune calibration statistique de ce type.

## Facteurs et poids

| Facteur | Poids | Justification |
|---|---|---|
| Specificite de la regle | 0.40 | Une regle avec plusieurs conditions combinees (AND) est moins susceptible de matcher par coincidence qu'une regle a une seule condition large - facteur le plus discriminant sur la fiabilite de la detection elle-meme |
| Taille du cluster correle | 0.35 | Une detection isolee (cluster de taille 1) est moins soutenue par le contexte qu'une detection appartenant a une chaine d'evenements correles (M3-02) |
| Force de la correlation | 0.25 | Le score moyen de correlation (M3-01) entre les evenements du cluster - un cluster faiblement correle (proche du seuil 0.5) soutient moins la conclusion qu'un cluster fortement correle |

Le total des poids vaut 1.0.

## Normalisation de chaque facteur

- **Specificite de la regle** : nombre de conditions AND distinctes dans la clause SQL generee (M2-01), normalise par un plafond de 5 conditions (specificite = min(nombre_conditions / 5, 1.0)). Une regle a 1 condition = 0.2, une regle a 5+ conditions = 1.0.
- **Taille du cluster** : normalisee par un plafond de 5 evenements (taille = min(taille_cluster / 5, 1.0)). Un cluster de 1 evenement = 0.2, un cluster de 5+ evenements = 1.0.
- **Force de correlation** : moyenne des scores de correlation (M3-01) entre toutes les paires d'evenements du cluster. Pour un cluster de taille 1, ce facteur vaut 0.0 par convention (aucune correlation a mesurer).

## Formule

confidence = 0.40 * rule_specificity + 0.35 * cluster_size_factor + 0.25 * correlation_strength

Le score final est compris entre 0.0 et 1.0.

## Workflow de validation (a suivre a l'implementation)

1. Definir cette formule theorique (fait, ci-dessus)
2. L'implementer fidelement
3. La tester sur les scenarios M5-05
4. Documenter les limites observees - PAS ajuster les poids pour obtenir un resultat
   different de celui produit par la formule telle que definie ici
