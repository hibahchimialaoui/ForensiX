# Validation de la correlation (M3-05)

## Limite methodologique : dataset M1-07

Le dataset M1-07 (UACME_59_Sysmon.evtx, T1548.002 - contournement UAC) est un
scenario a technique unique qui ne contient pas de chaine multi-evenements
representative d'un incident a coreler. C'est la meme limite methodologique
que M2-05 (ou le meme dataset ne correspondait a aucune regle Sigma curee).

Utiliser ce dataset pour tester le clustering produirait soit 1 cluster trivial
(tous les evenements regroupes par host + proximite temporelle), soit une mesure
sans reference de ground truth fiable. Ni l'un ni l'autre ne valide le moteur
de correlation.

## Approche retenue : jeu de tests multi-scenarios (src/forensix/correlation/validation.py)

3 scenarios construits a la main, chacun testant une propriete distincte du
moteur de correlation :

### Scenario A : chaine unique (4 evenements)

powershell.exe (PID 100) -> cmd.exe (PID 200, PPID 100) -> certutil.exe
(PID 300, PPID 200) -> connexion reseau (PID 300)

Verifie : la transitivite du clustering (A~B et B~C implique A, B, C dans le
meme cluster, meme si A et C ont un lien direct faible).

Resultat attendu : 1 cluster de 4 evenements.
Resultat obtenu : 1 cluster de 4 evenements. OK.

### Scenario B : deux incidents independants (4 evenements, 2 hosts)

Incident 1 (HOST-A) : wscript.exe -> powershell.exe
Incident 2 (HOST-B) : explorer.exe -> mshta.exe

Verifie : l'absence de fusion abusive inter-hosts (le score M3-01 attribue
0.0 au facteur host pour des hosts differents).

Resultat attendu : 2 clusters distincts.
Resultat obtenu : 2 clusters de 2 evenements chacun. OK.

### Scenario C : chaine + evenement isole (3 evenements, 2 hosts)

Chaine (HOST-A) : powershell.exe -> notepad.exe
Evenement isole (HOST-C) : svchost.exe (host different, sans lien)

Verifie : qu'un evenement sans correlation avec aucun autre reste dans son
propre cluster d'1 element (pas de fusion par defaut).

Resultat attendu : 2 clusters (1 de taille 2, 1 de taille 1).
Resultat obtenu : 2 clusters [2, 1]. OK.

## Limite assumee de ce jeu de tests

Comme pour M2-05, ce jeu de tests verifie la coherence logique du moteur
sur des scenarios construits, pas sa robustesse sur un volume ou une diversite
de trafic representatifs d'un environnement reel. Il valide que le clustering
fonctionne correctement selon sa specification (M3-01), pas qu'il detectera
tous les incidents dans un vrai SOC.

Un jeu d'evaluation plus large (variantes par technique, bruit ambiant, faux
positifs intentionnels dans le dataset) reste necessaire pour une evaluation
representative, prevue comme evolution future de ForensiX.
