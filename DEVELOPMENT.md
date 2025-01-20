# Dev setup

## Publishing (test pypy)

First create an account on [test pypi]() and generate a token.

Clean your worktree and tag your release to generate a valid version number (otherwise pypi will reject your release) :

```
git stash # clean your worktree
git tag 0.0.18rc1
git stash pop # restore your worktree
```

Then, publish using the Makefile to build and push the library : 

```
make clean && make build && make publish-test
```

## Publishing (production)

Make sure that you are on the maintainer list of the [pypi project](https://pypi.org/project/django-pyoidc/) and generate an API token for this project.

Clean your worktree and tag your release :

```
git stash # clean your worktree
git tag 0.0.1 # tag the release
git stash pop # tag your release
```

Build the python package :

```
make clean && make build
```

Publish it :

```
make publish
```


## Installation

```bash
pip install -r requirements/requirements.txt -r requirements/requirements-test.txt
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

## Running static type checking (mypy)

First install the dev dependencies :

```
pip install -r requirements/requirements.txt -r requirements/requirements-dev.txt
```

Then run mypy :

```
mypy django_pyoidc
```

## Running Tests

Check database settings in `tests/test_settings.py`, target a real PostgreSQL Host (You need a PostgreSQL version 12 or greater), for e2e tests check the `tests/e2e/settings.py` file.

```
python3 run_tests.py  # for unit tests
python3 run_e2e_tests.py  # for end to end tests
```

## Adding a dependency

Add the dependency to either `requirements/requirements.in`, `requirements/requirements-test.in` or `requirements/requirements-dev.in` 
depending on the usage of the dependency.

Then run :

```
pip install pip-tools
make update_all_deps
```

## Building local packages

You can build the package locally by running :

```
python -m build
```
