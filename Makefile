.PHONY: update_all_deps build clean publish-test

update_all_deps : requirements/requirements.txt requirements/requirements-dev.txt requirements/requirements-test.txt


requirements/requirements.txt : pyproject.toml
	pip-compile -o $@ $< --extra drf

requirements/requirements-dev.txt : requirements/requirements-dev.in requirements/requirements/requirements.txt
	pip-compile -o $@ $<

requirements/requirements-test.txt : requirements/requirements-test.in requirements/requirements-dev.in requirements/requirements.txt
	pip-compile $<

publish-test: 
	hatch publish -r test -u __token__

publish: 
	hatch publish -r main -u __token__

build:
	hatch build

clean:
	@rm -rf dist/
