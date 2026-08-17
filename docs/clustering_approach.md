# Approche de clustering (M3-02)

## Probleme

Le score de correlation (M3-01) ne compare que des paires d'evenements. Pour regrouper
plus de deux evenements en un cluster d'incident, il faut une regle explicite de
transitivite : si l'evenement A est correle a B, et B est correle a C, alors A, B et C
doivent former un seul cluster - meme si A et C, pris isolement, ont un score de
correlation directe inferieur au seuil.

## Algorithme choisi : Union-Find (disjoint-set)

Union-Find est une structure de donnees classique qui garantit :

- **Transitivite automatique** : fusionner (A, B) puis (B, C) place A, B et C dans le
  meme ensemble, sans code specifique pour gerer les chaines de correlation.
- **Determinisme strict** : pour un meme jeu d'evenements et les memes paires jugees
  correlees, la partition finale en clusters est identique quel que soit l'ordre de
  traitement des paires. C'est la contrainte de determinisme exigee en revue.
- **Complexite quasi-lineaire** : approprie pour le volume attendu du MVP (pas
  d'optimisation prematuree necessaire).

## Algorithme en detail

1. Chaque evenement commence comme son propre cluster (ensemble a un seul element).
2. Pour chaque paire d'evenements du meme host (comparer uniquement les evenements du
   meme host limite le nombre de paires a evaluer : le score M3-01 attribue de toute
   facon 0.0 au facteur host pour deux hosts differents, donc inutile de comparer les
   paires inter-hosts), si are_correlated(a, b) est vrai (M3-01), fusionner leurs
   ensembles.
3. A la fin, chaque ensemble distinct constitue un cluster.

## Determinisme : ce qui est garanti et ce qui ne l'est pas

Garanti : la partition finale (quels evenements finissent dans le meme cluster) est
independante de l'ordre de traitement des paires, propriete mathematique de Union-Find.

Non garanti et non pertinent : l'identifiant (UUID) attribue a chaque cluster differe
a chaque execution - ce n'est pas une violation du determinisme, seul le regroupement
des evenements est une propriete testee, pas l'identifiant genere.

## Limite assumee

La comparaison est limitee aux evenements du meme host, coherente avec la limite deja
posee en M3-01 (pas de correlation inter-hosts / mouvement lateral dans ce MVP).
