"""Download the public EVTX fixture used to validate the ForensiX ingestion pipeline.

Source: EVTX-ATTACK-SAMPLES by sbousseaden (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
licensed under GPL-3.0. The fixture is downloaded on demand rather than vendored into this
repository, to avoid embedding a GPL-licensed binary asset directly in a project declared
under a different license.
"""

import urllib.request
from pathlib import Path

DATASET_URL = (
    "https://raw.githubusercontent.com/sbousseaden/"
    "EVTX-ATTACK-SAMPLES/master/UACME_59_Sysmon.evtx"
)
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "evtx"
FIXTURE_PATH = FIXTURE_DIR / "UACME_59_Sysmon.evtx"


def download_fixture() -> Path:
    """Download the fixture if not already present locally, and return its path."""
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    if not FIXTURE_PATH.exists():
        urllib.request.urlretrieve(DATASET_URL, FIXTURE_PATH)
    return FIXTURE_PATH


if __name__ == "__main__":
    path = download_fixture()
    print(f"Fixture ready at: {path}")
