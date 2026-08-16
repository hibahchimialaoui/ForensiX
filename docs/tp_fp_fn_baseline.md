# Baseline TP/FP/FN (M2-05)

## Portee et limite methodologique

Le dataset reel de M1-07 (UACME_59_Sysmon.evtx, technique T1548.002 - contournement UAC)
ne correspond a aucune des 7 regles curees en M2-02 : l'executer contre nos regles
donnerait 0 detection partout, ce qui ne mesure rien d'exploitable.

Cette baseline utilise donc un jeu d'evaluation construit a la main (src/forensix/detection/evaluation.py) :
4 evenements positifs (un par regle pleinement operationnelle) et 4 evenements benins
partages. Elle mesure la coherence logique du pipeline de detection, pas la performance
du moteur sur un volume ou une diversite de trafic representatifs d'un environnement reel.

Les 3 regles partielles (M2-02 : OriginalFileName et Initiated non mappes) sont exclues
de cette mesure, pas silencieusement ignorees - elles ne peuvent pas etre evaluees tant
que ces champs ne sont pas ajoutes au FIELD_MAPPING.

## Resultats

| Regle | Sigma ID | TP | FP | FN |
|---|---|---|---|---|
| Suspicious execution path | 3dfd06d2-eaf4-4532-9555-68aca59f57c4 | 1 | 0 | 0 |
| PowerShell download pattern | e6c54d94-498c-4562-a37c-b469d8e9a275 | 1 | 0 | 0 |
| Startup folder persistence | 28208707-fe31-437f-9a7f-4b1108b94d2e | 1 | 0 | 0 |
| Sync Center suspicious connection | 9f2cc74d-78af-4eb2-bb64-9cd1d292b87b | 1 | 0 | 0 |

Verifie empiriquement le 16/08/2026 : les 4 regles obtiennent TP=1, FP=0, FN=0 sur leur
cas positif et benin respectifs. Le cas le plus significatif est celui de la regle
mobsync : une connexion vers une IP privee (192.168.1.10) n'a genere aucun faux positif,
confirmant que le filtre CIDR (decouvert fonctionnel en M2-02) se comporte correctement
sur un cas construit specifiquement pour le tester.

## Ce que cette baseline ne mesure pas

- Le taux de faux positifs sur un trafic reel et varie (le jeu d'evaluation ne contient
  qu'un seul cas benin par regle)
- La performance sur volume (nombre d'evenements traites par seconde) - prevu en M7
- Les 3 regles partielles (necessitent l'extension du FIELD_MAPPING, backlog documente
  en M2-02)
- La robustesse face a des variations du scenario d'attaque (une seule variante testee
  par technique)

## Prochaine etape

Un jeu d'evaluation plus large, avec plusieurs variantes par technique et davantage de
cas benins realistes, est necessaire avant de pouvoir presenter une mesure TP/FP/FN
representative de la qualite reelle du moteur. Cette baseline constitue le point de
depart documente pour cette evolution future, pas une conclusion definitive sur la
performance de ForensiX.
