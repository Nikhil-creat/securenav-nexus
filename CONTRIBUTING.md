# Contributing
1. Fork, branch from `main`.
2. `pip install -r requirements/dev.txt && pytest -q` and `flake8 src sim scripts tests --max-line-length 170`.
3. Add tests for new behaviour (`tests/`); security-relevant changes need a TARA note in `documentation/TARA.md`.
4. Open a pull request describing the threat or feature addressed.
