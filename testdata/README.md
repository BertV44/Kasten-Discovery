# Test fixtures

Drop an anonymised KDL discovery report here as `report.json` and the
fixture-backed tests will run against it:

    go test ./...

Without it those tests **skip** rather than fail, so a fresh clone stays green.
Point them at any other report with:

    KDL_FIXTURE=/path/to/report.json go test ./...

Reports are gitignored (`*.json` in this directory) on purpose: they are derived
from customer clusters, and this repository is public. Anonymise before
committing anything here, and only commit a fixture deliberately.
