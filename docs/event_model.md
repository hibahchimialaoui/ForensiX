# Common Event Model

ForensiX normalise tous les evenements ingeres (Windows Event Logs, Sysmon, et futures sources) vers un modele commun : `NormalizedEvent`, defini dans `src/forensix/models/event.py`.

## Principe

Le modele distingue deux categories de champs :

- **Champs obligatoires**, presents sur tout evenement quelle que soit sa source : `id`, `timestamp`, `host`, `source`, `event_id`, `event_type` (`user` est optionnel car certains evenements systeme n'ont pas d'utilisateur associe).
- **Sous-objets optionnels**, specifiques a certains types d'evenements : `process` (creation de processus), `file` (creation/acces fichier), `network` (connexion reseau).

Un evenement d'authentification Windows n'a pas de champ `process` rempli ; un evenement Sysmon de connexion reseau n'a pas de champ `file` rempli. Le modele reste valide dans les deux cas plutot que de forcer un remplissage artificiel.

## Champ raw_event

Chaque `NormalizedEvent` conserve l'evenement source brut dans `raw_event` (dictionnaire libre), pour deboguer le mapping et preserver une chaine de preuve complete meme si le modele normalise s'avere incomplet plus tard.

## Ajouter une nouvelle source

Pour integrer une nouvelle source d'evenements (ex. Linux logs, futur milestone) :

1. Ecrire un parser qui lit la source brute
2. Mapper les champs vers `NormalizedEvent`, en remplissant uniquement les sous-objets pertinents
3. Conserver l'evenement brut original dans `raw_event`

Aucune modification du modele lui-meme n'est necessaire, sauf si la nouvelle source introduit une categorie d'information totalement nouvelle (auquel cas un nouveau sous-modele optionnel peut etre ajoute, sans casser les sources existantes).
