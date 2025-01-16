.PHONY: update_all_deps

update_all_deps : requirements.txt requirements-dev.txt requirements-test.txt


requirements/requirements.txt : pyproject.toml requirements/requirements.in
	pip-compile $< --extra drf


requirements/requirements-dev.txt : requirements-dev.in requirements.in
	pip-compile $<

requirements/requirements-test.txt : requirements-test.in requirements.in requirements-dev.in
	pip-compile $<
