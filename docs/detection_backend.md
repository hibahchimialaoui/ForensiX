# Detection Backend (pySigma -> ForensiX Event Store)

## Chaine de transformation

Sigma rule (YAML) -> pySigma parser -> Field mapping pipeline (Sigma field names -> colonnes EventRecord) -> ForensixPostgresBackend (src/forensix/detection/backend.py) -> Fragment SQL WHERE-clause -> Applique via SQLAlchemy text() sur EventRecord

## Mapping des champs

| Champ Sigma | Colonne EventRecord |
|---|---|
| Image | process_name |
| CommandLine | process_command_line |
| ParentProcessId | process_ppid |
| ProcessId | process_pid |
| TargetFilename | file_path |
| DestinationIp | network_destination_ip |
| DestinationPort | network_destination_port |
| EventID | event_id |

Seuls ces 8 champs sont couverts, car ce sont les seuls utilises par les regles selectionnees en M2-02. Un champ Sigma absent de ce mapping passe inchange et provoquera une erreur SQL a l'execution (colonne inexistante), pas au chargement de la regle.

## Limites connues

### 1. Type de la colonne event_id (String vs Integer)

`EventRecord.event_id` est une colonne `String` (voir M1-06 : les event_id Windows/Sysmon sont geres comme des chaines dans tout le pipeline d'ingestion). Mais une regle Sigma exprime generalement `EventID` comme un nombre (ex. `EventID: 1`), et notre backend le traduit en litteral numerique non quote : `"event_id" = 1`.

PostgreSQL rejette la comparaison d'une colonne texte avec un litteral numerique sans cast explicite (`operator does not exist: character varying = integer`).

**Consequence :** toute regle Sigma filtrant sur `EventID` echouera a l'execution telle quelle.

**Traitement prevu :** le pipeline d'execution (M2-03) devra caster les valeurs numeriques du champ `event_id` en texte avant execution, ou notre backend devra etre etendu pour forcer le quoting sur ce champ specifique. Non resolu dans M2-01 : cette issue se limite a definir la chaine de transformation, pas a la durcir pour tous les cas.

### 2. Couverture des operateurs Sigma

Seuls les operateurs suivants sont implementes et testes :
- Egalite simple (`field: value`)
- Wildcard / contains / startswith / endswith (traduits en `LIKE`)
- AND / OR / NOT / IS NULL
- Plages CIDR (`|cidr`), decomposees automatiquement par pySigma en clauses LIKE equivalentes pour les plages alignees sur des limites d'octet - verifie empiriquement en M2-02

Non implementes : expressions regulieres (`|re`), comparaisons champ-a-champ, et toutes les fonctionnalites de correlation Sigma (hors scope MVP-A).

### 3. Pas de gestion de la casse

Les comparaisons `LIKE` generees sont sensibles a la casse par defaut sous PostgreSQL, alors que Sigma ne specifie pas systematiquement la sensibilite a la casse attendue. A verifier au cas par cas lors de la selection des regles en M2-02.

### 4. Approche choisie : fragment SQL texte, pas de constructeur de requete type-safe

Le backend produit un fragment de texte SQL (`"col" LIKE 'valeur'`) plutot qu'une structure SQLAlchemy `Query.filter()` composable. Ce choix est acceptable ici car les noms de colonnes generes proviennent uniquement de notre `FIELD_MAPPING` fixe (jamais d'un champ arbitraire fourni par une regle Sigma non validee), ce qui elimine le risque d'injection via les noms de colonnes. Les valeurs elles-memes restent quotees par pySigma. A revalider si le mapping devient un jour dynamique ou controle par un tiers.

### 5. Bug trouve et corrige en M2-02 : group_expression manquant

Le premier jeu de tests M2-01 (2 regles simples, sans liste de valeurs) n'exercait jamais de regroupement entre parentheses. En testant 7 regles reelles en M2-02, 5 ont echoue avec l'erreur "Group expressions are not supported by the backend". Cause : l'attribut group_expression n'etait pas defini sur ForensixPostgresBackend. Corrige par l'ajout de group_expression = "({expr})". Lecon retenue : des tests unitaires qui ne couvrent que des cas simples peuvent donner une fausse confiance ; verifier sur des regles reelles et variees reste necessaire avant de considerer un backend pret.
