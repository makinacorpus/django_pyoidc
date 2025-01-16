.PHONY: update_all_deps

update_all_deps : requirements/requirements.txt requirements/requirements-dev.txt requirements/requirements-test.txt


requirements/requirements.txt : pyproject.toml requirements/requirements.in
	pip-compile -o $@ $< --extra drf


requirements/requirements-dev.txt : requirements/requirements-dev.in requirements/requirements.in
	pip-compile -o $@ $<

requirements/requirements-test.txt : requirements/requirements-test.in requirements/requirements.in requirements/requirements-dev.in
	pip-compile -o $@ $<
