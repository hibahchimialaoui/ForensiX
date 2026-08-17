# Score de correlation (M3-01)

## Principe

Le score de correlation mesure la probabilite que deux evenements appartiennent au meme
incident. Il combine 5 facteurs independants, chacun normalise entre 0 et 1, combines par
une moyenne ponderee. Cette specification est ecrite AVANT toute implementation, pour
eviter le biais consistant a ajuster les poids apres coup jusqu'a obtenir un resultat
qui "marche" sur un cas particulier. Toute modification ulterieure des poids ou du seuil
devra etre justifiee par les resultats du jeu de tests M3-05, jamais par un ajustement
iteratif non documente.

## Facteurs et poids

| Facteur | Poids | Justification |
|---|---|---|
| Meme host | 0.30 | Un incident implique quasi-systematiquement une seule machine compromise a la fois dans notre scope MVP (pas de mouvement lateral modelise) - facteur le plus discriminant |
| Proximite temporelle | 0.25 | Les etapes d'un incident se succedent typiquement en secondes ou minutes, rarement en heures - facteur fort mais moins absolu que le host |
| Relation PID/PPID | 0.20 | Un lien parent-enfant direct entre processus est une preuve forte de chaine causale, mais absent pour la plupart des paires d'evenements (donc poids inferieur au temps/host qui s'appliquent a toute paire) |
| Meme utilisateur | 0.15 | Signal utile mais faible : de nombreux processus systeme partagent le meme compte (SYSTEM, service accounts), donc moins discriminant que le host |
| Relation fichier/reseau partage | 0.10 | Signal le plus faible et le plus rare (peu d'evenements partagent un chemin de fichier ou une IP identique), mais confirme fortement le lien quand il existe |

Le total des poids vaut 1.0.

## Normalisation de chaque facteur

- **Meme host** : 1.0 si host identique, 0.0 sinon (binaire).
- **Proximite temporelle** : decroissance lineaire de 1.0 (ecart nul) a 0.0 (ecart >= 15 minutes, WINDOW_SECONDS = 900). Au-dela de cette fenetre, le facteur est fixe a 0.0 plutot que negatif.
- **Relation PID/PPID** : 1.0 si le PID de l'un correspond au PPID de l'autre (dans un sens ou l'autre), 0.0 sinon.
- **Meme utilisateur** : 1.0 si user identique et non vide, 0.0 sinon (deux valeurs vides/None ne comptent pas comme une correspondance).
- **Relation fichier/reseau partage** : 1.0 si les deux evenements partagent le meme file_path OU la meme network_destination_ip (non vide), 0.0 sinon.

## Formule

score = 0.30 * same_host + 0.25 * temporal_proximity + 0.20 * pid_ppid_relation + 0.15 * same_user + 0.10 * shared_file_or_network

Le score final est compris entre 0.0 et 1.0.

## Seuil de decision

**Seuil initial : 0.5**

Justification : avec ce seuil, deux evenements du meme host (0.30) survenant dans la
meme minute (proximite temporelle proche de 1.0, soit environ 0.25) atteignent deja
0.55 et sont consideres comme correles, meme sans lien PID/PPID ni utilisateur commun.
C'est le comportement mimimal attendu d'un moteur de correlation temporelle+host. Ce
seuil sera valide (et ajuste si necessaire, avec justification) contre le jeu de tests
multi-scenarios de M3-05.

## Limite assumee

Ce score ne modelise pas le mouvement lateral (changement de host au cours d'un meme
incident) - une limite explicite du MVP, coherente avec le scope actuel de ForensiX
(ingestion Windows/Sysmon sur un host a la fois, pas de correlation inter-hosts).

