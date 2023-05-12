# Dev setup

## Installation

```bash
pip install .['dev']
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