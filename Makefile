.PHONY: update_all_deps

update_all_deps : requirements.txt requirements-dev.txt requirements-test.txt


requirements.txt : pyproject.toml
	pip-compile $< --extra drf


requirements-dev.txt : requirements-dev.in requirements.txt
	pip-compile $<

requirements-test.txt : requirements-test.in requirements.txt
	pip-compile $<
