# Dev setup

## Publishing (test pypy)

First create an account on [test pypi]() and generate a token.

Clean your worktree and tag your release to generate a valid version number (otherwise pypi will reject your release) :

```bash
git stash # clean your worktree
git tag 0.0.18rc1
git stash pop # restore your worktree
```

Then, publish using the Makefile to build and push the library : 

```bash
make clean && make build && make publish-test
```

## Publishing (production)

Make sure that you are on the maintainer list of the [pypi project](https://pypi.org/project/django-pyoidc/) and generate an API token for this project.

Clean your worktree and tag your release :

```bash
git stash # clean your worktree
git tag 0.0.1 # tag the release
git stash pop # tag your release
```

Build the python package :

```bash
make clean && make build
```

Publish it :

```bash
make publish
```


## Installation

```bash
pip install -r requirements/requirements.txt -r requirements/requirements-test.txt
# Or use specific python versions folders:
pip install -r requirements/3.12/requirements.txt -r requirements/3.12/requirements-dev.txt
```

## Enable pre-commit

```bash
pre-commit install
```

## Writing documentation

Run a live documentation server :

```bash
sphinx-autobuild docs docs/_build/html
```

## Running static type checking (mypy)

First install the dev dependencies :

```bash
pip install -r requirements/requirements.txt -r requirements/requirements-dev.txt
# Or use specific python versions folders:
pip install -r requirements/3.12/requirements.txt -r requirements/3.12/requirements-dev.txt
```

Then run mypy :

```bash
mypy django_pyoidc
```

## Running Tests


First install the **tests*** dependencies :

```bash
pip install \
  -r requirements/requirements.txt \
  -r requirements/requirements-dev.txt \
  -r requirements/requirements-test.txt
# Or use specific python versions folders:
pip install \
  -r requirements/3.12/requirements.txt \
  -r requirements/3.12/requirements-dev.txt \
  -r requirements/3.12/requirements-test.txt
```

Check database settings in `tests/test_settings.py`, target a real PostgreSQL Host (You need a PostgreSQL version 12 or greater), for e2e tests check the `tests/e2e/settings.py` file.

```bash
python3 run_tests.py  # for unit tests
python3 run_e2e_tests.py  # for end to end tests
```

## Adding a dependency

Add the dependency to either `requirements/requirements.in`, `requirements/requirements-test.in` or `requirements/requirements-dev.in` 
depending on the usage of the dependency.

Then run :

```bash
pip install pip-tools
make update_all_deps
```

## Building local packages

You can build the package locally by running :

```bash
python -m build
```
