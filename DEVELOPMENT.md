# Dev setup

## Installation

```bash
pip install -r requirements.txt -r requirements-test.txt
```

## Enable pre-commit

```
pre-commit install
```

## Writing documentation

Run a live documentation server :

```
sphinx-autobuild docs docs/_build/html
```

## Running Tests

Check database settings in `tests/test_settings.py`, target a real PostgreSQL Host (You need a PostgreSQL version 12 or greater), for e2e tests check the `tests/e2e/settings.py` file.

```
python3 run_tests.py  # for unit tests
python3 run_e2e_tests.py  # for end to end tests
```

## Adding a dependency

Add the dependency to either `requirements.in`, `requirements-test.in` or `requirements-dev.in` 
depending on the usage of the dependency.

Then run :

```
pip install pip-tools
make update_all_deps
```

FIXME: possible alternative for tests requirements would be:
```
python -m piptools compile --extra test -o requirements-test.txt pyproject.toml
```
