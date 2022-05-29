# Contributing to Coraza

>**Note**: We take Coraza's security and the trust of our community seriously. If
> you believe you have found a security issue in Coraza or any of its
> components, please responsibly disclose by contacting us. See
> [SECURITY.md](https://github.com/corazawaf/coraza/blob/v2/master/SECURITY.md)
> for details.


We are striving to support an open community for the Coraza Project. We support
our contributors, please don't feel afraid or unsure of submitting feedback or asking a question.

## Contributions

* Get in touch via the [OWASP Slack Community](https://owasp.org/slack/invite) (#coraza)
* Provide feedback and report potential bugs
* Suggest enhancements to the project
* Perform tests and increase test coverage
* Fix a [Bug](https://github.com/corazawaf/coraza/issues?q=is%3Aopen+is%3Aissue+label%3Abug) or implement an [Enhancement](https://github.com/corazawaf/coraza/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement)
* Improve our Documentation, the [Coraza Website Repo](https://github.com/corazawaf/coraza.io) is on Github.

## Reporting an Issue

* Security related issues are covered by the [Security Policy](https://github.com/corazawaf/coraza/blob/v2/master/SECURITY.md)
* Make sure you test against the latest version, it's possible the issue was
  already fixed. However if you are on an older version of Coraza and feel the
  issue is critical, please let us know.
* Check existing [Issues](https://github.com/corazawaf/coraza/issues) (open and closed) to ensure it was not already reported.
* Provide a detailed description and a reproducible test case in a new [Issue](https://github.com/corazawaf/coraza/issues/new).
  Be sure to include as much relevant information as possible, a **code sample** or an **test case** demonstrating the fault helps us to reproduce your problem.

## Patches
Did you write a patch that fixes a bug?

* Open a new GitHub pull request which includes your changes.
* Please include a description which clearly describes the change. Include the relevant issue number if applicable.
* Before submitting, you can test your code using [pre-commit](https://pre-commit.com/) to validate your pull request will pass our set of tests.

## Enhancements

Do you intend to add a new feature or change an existing one?
* Suggest your change in the [Discussion](https://github.com/corazawaf/coraza/discussions/categories/ideas) and start writing code.
* Do not open an issue on GitHub until you have collected positive feedback about the change. GitHub issues are primarily intended for bug reports and fixes.
* There are many TODOs, functionalities, fixes, bug reports, and any help you can provide. Just send your pull request.

Run from the repository root:
```sh
egrep -Rin "TODO|FIXME" -R --exclude-dir=vendor *
```


## Questions
Do you have questions about the source code? Ask any question about how to use Coraza in the [community](https://github.com/corazawaf/coraza/discussions/categories/q-a).

## Testing

Coraza uses Go's built-in test tool. Examples (run from the repository root):

- `go test -v`
- `go test -v -race ` use to enable the built-in data race detector
- `go test -run TestDefaultWriters -v ./loggers` run all tests loggers package with name substring `TestDefaultWriters`

When a pull request is opened CI will run all tests to verify the change.
Before submitting you can commit using [pre-commit](https://pre-commit.com) to
validate your pull request passes our test set:

```sh
pip install pre-commit
pre-commit run --all-files
```

You can also install the pre-commit git hook by running
```sh
pre-commit install
```

_________________

The Coraza project is a community effort. We encourage you to pitch in and join the team!

Thanks! :heart: :heart: :heart:

Coraza Team
