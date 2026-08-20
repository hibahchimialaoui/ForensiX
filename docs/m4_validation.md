# Validation multi-clusters et multi-techniques (M4-04)

## Note sur le scenario negatif

La description validee en revue demandait un "evenement/detection sans mapping ATT&CK"
comme scenario negatif. En verifiant, aucune des 4 regles pleinement operationnelles
(M2-02) n'a de technique vide : Suspicious execution path (T1036), PowerShell download
(T1059.001), Startup persistence (T1204.002 + T1547.001), Sync Center (T1055 + T1218)
ont toutes au moins une technique. Seule la regle "Office uncommon ports" a zero
technique, mais elle est classee "partielle" (champ Initiated non mappe) et echoue a
l'execution plutot que de produire un match propre sans technique.

Fabriquer artificiellement un cas positif sans technique aurait ete plus trompeur que
de reconnaitre cette limite. Le scenario negatif retenu est donc : un evenement sans
aucune detection ne doit produire aucune entree de justification - deja valide
structurellement en M4-03 (test_clean_event_produces_no_justification_entry) et
complete par le test unitaire de M4-02 (une regle sans tag de technique retourne une
liste vide). Ce jeu de validation multi-clusters le revalide dans un contexte plus
large (plusieurs clusters simultanes).

## Jeu de validation (src/forensix/timeline/validation.py)

- Cluster A (host A, 1 evenement) : execution depuis Perflogs -> technique T1036
- Cluster B (host B, 2 evenements lies par PID) : PowerShell cree un fichier dans
  Startup -> techniques T1204.002 et T1547.001
- Evenement isole (host A, sans lien avec le cluster A malgre le meme host, car
  hors fenetre temporelle et sans relation PID/PPID/fichier/reseau) : aucune detection,
  scenario negatif

## Resultats

Verifie empiriquement le 17/08/2026, chaine complete M3 (clustering) + M4 (timeline,
mapping ATT&CK, justification), contre PostgreSQL reel :

| Cluster | Taille | Techniques ATT&CK | Entrees timeline |
|---|---|---|---|
| B | 2 | T1204.002, T1547.001 | 2 |
| A | 1 | T1036 | 1 |
| Isole | 1 | (aucune) | 0 justification |

- Le clustering regroupe correctement les 2 evenements lies du cluster B (transitivite
  M3-02) et separe correctement les 3 groupes.
- La timeline produit le bon nombre d'entrees pour chaque cluster.
- Le mapping ATT&CK (M4-02) associe les bonnes techniques a chaque cluster.
- La chaine de justification (M4-03) ne perd aucune reference entre la technique et
  la preuve brute, et ne fabrique aucune entree pour l'evenement isole.

## Limite assumee

Comme pour M2-05 et M3-05, ce jeu de validation confirme la coherence logique de la
chaine complete sur un dataset construit, pas sa robustesse sur un volume ou une
diversite de trafic representatifs d'un environnement reel.
