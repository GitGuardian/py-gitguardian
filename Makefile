SHELL :=/bin/bash
.PHONY: all test coverage black flake8
.SILENT:

test ?= tests

all:
	echo "Usage :"
	echo "      make test"           # Run tests
	echo "      make coverage"           # Run tests and coverage
	echo "      make black"          # Run black formatter on python code
	echo "      make flake8"          # Run flake8 linter on python code
	echo "      make isort"          # Run isort linter on python code

test:
	pipenv run nosetests $(test)

coverage:
	pipenv run coverage run --source pygitguardian -m nose tests && pipenv run coverage report --fail-under=80

black:
	pipenv run black --config black.toml .

flake8:
	pipenv run flake8

isort:
	pipenv run isort **/*.py
