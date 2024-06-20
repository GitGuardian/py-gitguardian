## Contributing to pygitguardian

## Getting involved

Development is coordinated via the issue tracker exclusively.

If you want to propose large changes be sure to communicate with other contributors
through an issue tagged as `feature request` about the design and the benefits of such change.

## Bug Reporting

When submitting a bug report be sure that:

- You are using the latest version of the package
- There are no issues describing the same behaviour on the issue tracker

## Dev environment

```bash
pdm install -G dev
pdm run pre-commit install -f --hook-type commit-msg --hook-type pre-commit
```

## Testing

Pygitguardian testing is done with `pytest`. You should make sure your changes don't report any error on:

```
make test
```

## Conventions

pygitguardian follows conventional commit messages [link](https://www.conventionalcommits.org/).

### Line length

Line length in the one enforced by Black: 88 characters.

### DocString

- Use sphinx style docstrings
- There are never too many docstrings
- If the docstring will take more than 1 line, start directly below """
- The first sentence starts with a capital letter and ends with a point. This sentence is separated from the others by a blank line
- Docstrings must have :params: if the function has 2 or more arguments.
- All docstrings must state the return object and raised exception with :return: and :raise:

### Changelog

We use [scriv](https://github.com/nedbat/scriv) to manage our changelog. It is automatically installed by `pdm install -G dev`.

All user visible changes must be documented in a changelog fragment. You can create one with `scriv create`. If your pull request only contains non-visible changes (such as refactors or fixes for regressions introduced _after_ the latest release), then apply the `skip-changelog` label to the pull request.
