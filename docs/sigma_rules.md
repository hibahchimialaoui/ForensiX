# Regles Sigma selectionnees (M2-02)

7 regles reelles, issues du depot officiel SigmaHQ/sigma, choisies pour leur compatibilite
avec les sources actuellement ingerees par ForensiX (Sysmon event_id 1/3/11) et avec le
mapping de champs defini par notre backend (docs/detection_backend.md).

Principe : moins de regles, bien justifiees et verifiees, plutot que beaucoup de regles
copiees sans verification. 4 des 7 sont pleinement compatibles avec notre mapping de
champs actuel ; 3 sont documentees comme partiellement compatibles - conservees dans la
selection pour illustrer concretement les limites posees en M2-01, pas cachees.

## Regle 1 - Process Execution From A Potentially Suspicious Folder

- Sigma ID: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
- Source: SigmaHQ/sigma, rules/windows/process_creation/proc_creation_win_susp_execution_path.yml
- Target Event ID (ForensiX): Sysmon 1 (Process Creation)
- ATT&CK technique: T1036 (Masquerading)
- Scenario couvert: execution d'un processus depuis un dossier inhabituel (Perflogs, dossiers systeme detournes, etc.)
- Champs utilises: Image (contains)
- Compatibilite: Complete - tous les champs sont mappes
- Detection attendue: la ligne process_name contenant un des chemins suspects declenche
- Limites connues: aucune specifique au backend ForensiX ; faux positifs possibles sur des installateurs legitimes utilisant ces chemins

## Regle 2 - Suspicious PowerShell Download and Execute Pattern

- Sigma ID: e6c54d94-498c-4562-a37c-b469d8e9a275
- Source: SigmaHQ/sigma, rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml
- Target Event ID (ForensiX): Sysmon 1 (Process Creation)
- ATT&CK technique: T1059.001 (PowerShell)
- Scenario couvert: telechargement et execution via PowerShell (IEX + WebClient/DownloadString)
- Champs utilises: CommandLine (contains)
- Compatibilite: Complete - tous les champs sont mappes
- Detection attendue: la ligne process_command_line contenant un des motifs de telechargement declenche
- Limites connues: la regle source precise que la comparaison doit etre insensible a la casse ; notre backend genere du LIKE sensible a la casse sous PostgreSQL (limite documentee en M2-01, section 3)

## Regle 3 - Suspicious Startup Folder Persistence

- Sigma ID: 28208707-fe31-437f-9a7f-4b1108b94d2e
- Source: SigmaHQ/sigma, rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml
- Target Event ID (ForensiX): Sysmon 11 (File Create)
- ATT&CK technique: T1547.001 (Boot or Logon Autostart Execution), T1204.002 (User Execution)
- Scenario couvert: creation d'un fichier a extension suspecte dans le dossier Startup Windows
- Champs utilises: TargetFilename (contains, endswith)
- Compatibilite: Complete - tous les champs sont mappes
- Detection attendue: la ligne file_path correspondant au chemin Startup + une extension suspecte declenche
- Limites connues: aucune specifique au backend ForensiX

## Regle 4 - Suspicious Encoded PowerShell Command Line

- Sigma ID: ca2092a1-c273-4878-9b4b-0d60115bf5ea
- Source: SigmaHQ/sigma, rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml
- Target Event ID (ForensiX): Sysmon 1 (Process Creation)
- ATT&CK technique: T1059.001 (PowerShell)
- Scenario couvert: execution de PowerShell avec une commande encodee en base64 (technique classique, ex. Emotet)
- Champs utilises: Image, CommandLine, OriginalFileName
- Compatibilite: Partielle - OriginalFileName n'est pas dans notre FIELD_MAPPING (docs/detection_backend.md). La regle utilise ce champ en alternative (OR) a Image, ce qui provoquera une erreur SQL a l'execution (colonne inexistante) tant que le mapping n'est pas etendu
- Detection attendue (une fois le mapping etendu): process_name se terminant par powershell.exe/pwsh.exe ET process_command_line contenant un motif d'encodage
- Limites connues: necessite l'ajout d'OriginalFileName au FIELD_MAPPING avant d'etre pleinement fonctionnelle ; traite comme dette technique documentee, pas comme un blocage de cette issue

## Regle 5 - Office Application Initiated Network Connection Over Uncommon Ports

- Sigma ID: 3b5ba899-9842-4bc2-acc2-12308498bf42
- Source: SigmaHQ/sigma, rules/windows/network_connection/net_connection_win_office_uncommon_ports.yml
- Target Event ID (ForensiX): Sysmon 3 (Network Connection)
- ATT&CK tactic: Command and Control
- Scenario couvert: application Office (Word, Excel, Outlook) initiant une connexion reseau sur un port inhabituel
- Champs utilises: Initiated, Image, DestinationPort
- Compatibilite: Partielle - le champ Initiated (booleen indiquant si la connexion est sortante) n'est pas dans notre modele NormalizedEvent/EventRecord actuel
- Detection attendue (une fois le champ ajoute): process_name d'une app Office + network_destination_port hors de la liste des ports courants
- Limites connues: necessite l'ajout d'un champ "initiated" au Common Event Model (M1-03) et a EventRecord (M1-06) ; hors scope de cette issue, notee comme evolution future

## Regle 6 - Microsoft Sync Center Suspicious Network Connections

- Sigma ID: 9f2cc74d-78af-4eb2-bb64-9cd1d292b87b
- Source: SigmaHQ/sigma, rules/windows/network_connection/net_connection_win_susp_outbound_mobsync_connection.yml
- Target Event ID (ForensiX): Sysmon 3 (Network Connection)
- ATT&CK technique: T1055 (Process Injection), T1218 (System Binary Proxy Execution)
- Scenario couvert: mobsync.exe (Sync Center) initiant une connexion vers une IP publique - LOLBIN classique
- Champs utilises: Image, DestinationIp (avec filtre CIDR sur les plages privees)
- Compatibilite: Complete - le filtre CIDR (|cidr) fonctionne reellement : pySigma decompose automatiquement les plages en clauses LIKE equivalentes, verifie empiriquement en tache 4 (l'hypothese initiale de non-support etait incorrecte, corrigee dans docs/detection_backend.md section 5)
- Detection attendue: connexion initiee par mobsync.exe vers une IP hors des plages privees standard declenche
- Limites connues: aucune specifique a cette regle

## Regle 7 - Suspicious Download Via Certutil.EXE

- Sigma ID: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
- Source: SigmaHQ/sigma, rules/windows/process_creation/proc_creation_win_certutil_download.yml
- Target Event ID (ForensiX): Sysmon 1 (Process Creation)
- ATT&CK technique: T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files or Information)
- Scenario couvert: certutil.exe utilise comme LOLBIN pour telecharger un fichier (urlcache/verifyctl)
- Champs utilises: Image, OriginalFileName, CommandLine
- Compatibilite: Partielle - meme limite que la Regle 4 (OriginalFileName non mappe)
- Detection attendue (une fois le mapping etendu): process_name se terminant par certutil.exe ET process_command_line contenant un flag de telechargement ET le mot http
- Limites connues: identique a la Regle 4

## Synthese

| Regle | ATT&CK | Event ID cible | Compatibilite |
|---|---|---|---|
| Suspicious execution path | T1036 | Sysmon 1 | Complete |
| PowerShell download pattern | T1059.001 | Sysmon 1 | Complete |
| Startup folder persistence | T1547.001 | Sysmon 11 | Complete |
| Encoded PowerShell command | T1059.001 | Sysmon 1 | Partielle (OriginalFileName) |
| Office uncommon ports | Command and Control | Sysmon 3 | Partielle (Initiated) |
| Sync Center suspicious connection | T1055, T1218 | Sysmon 3 | Complete |
| Certutil download | T1105, T1027 | Sysmon 1 | Partielle (OriginalFileName) |

4 regles pleinement operationnelles des M2-03 (Regles 1, 2, 3, 6). 3 regles documentees
comme dette technique explicite (extension du FIELD_MAPPING pour couvrir OriginalFileName
pour les Regles 4 et 7, et pour couvrir Initiated pour la Regle 5), a traiter selon la
priorite du backlog plutot que bloquer cette issue.

Note de methode : la compilation reussie d'une regle (pySigma genere du SQL sans erreur)
ne garantit pas son execution correcte contre de vraies donnees - deux choses distinctes
verifiees separement en tache 4 (compilation via compile_rule_to_where_clause, puis
execution reelle contre PostgreSQL pour les regles marquees partielles, qui a confirme
les erreurs de colonne inexistante predites).




