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
pip-compile requirements.in # freeze package versions
pip-compile requirements-test.in
```
