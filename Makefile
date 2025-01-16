.PHONY: update_all_deps

update_all_deps : requirements/requirements.txt requirements/requirements-dev.txt requirements/requirements-test.txt


requirements/requirements.txt : pyproject.toml
	pip-compile -o $@ $< --extra drf

requirements/requirements-dev.txt : requirements/requirements-dev.in requirements/requirements/requirements.txt
	pip-compile -o $@ $<

requirements/requirements-test.txt : requirements/requirements-test.in requirements/requirements-dev.in requirements/requirements.txt
	pip-compile $<
