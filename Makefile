SHELL :=/bin/bash
.PHONY: all test coverage black flake8
.SILENT:

test ?= tests

all:
	echo "Targets:"
	echo "  test            Run tests"
	echo "  coverage        Run tests with coverage"
	echo "  lint            Run all linters"

test:
	uv run pytest --disable-pytest-warnings -vvv $(test)

coverage:
	uv run coverage run --source pygitguardian -m pytest --disable-pytest-warnings && uv run coverage report --fail-under=80

lint:
	pre-commit run --all
