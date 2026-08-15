# ForensiX

Evidence-driven Digital Forensics & Incident Response platform.

## Getting Started

Prerequisites: Docker Desktop.

```bash
docker compose up --build
```

The API will be available at http://localhost:8000, with a health check at http://localhost:8000/health.

## Test Dataset

ForensiX uses a real public EVTX sample to validate the ingestion pipeline end-to-end.

- Source: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by sbousseaden, licensed under GPL-3.0
- Fixture: `UACME_59_Sysmon.evtx`
- Scenario label (from filename): UACME method 59
- ATT&CK mapping: T1548.002 - Bypass User Account Control (mapping is at technique level, per the source repository documentation, not procedure level)
- Format: Sysmon EVTX

The fixture is downloaded on demand rather than vendored into this repository, to avoid embedding a GPL-licensed binary asset directly in a project declared under a different license.

```bash
python scripts/download_test_dataset.py
```

Note: this single fixture validates that the pipeline correctly ingests a real positive scenario. It is not, on its own, an evaluation dataset - measuring detection true/false positive/negative rates requires a broader dataset with both positive and negative (benign) scenarios, planned for a later milestone.
