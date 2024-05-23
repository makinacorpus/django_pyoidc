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

Check database settings in tests/test_settings.py, target a real PostgreSQL Host (You need a PostgreSQL version 12 or greater).

```
python3 runtests.py
```

## Adding a dependency

Add the dependency to either `requirements.in` or `requirements-test.in`.

Then run :

```
pip install pip-tools
pip-compile --output-file=requirements.txt pyproject.toml # freeze package versions
pip-compile --output-file=requirements-test.txt requirements-test.in
```

FIXME: possible alternative for tests requirements would be:
```
python -m piptools compile --extra test -o requirements-test.txt pyproject.toml
```
