# Contributing to Coraza

>**Note**: We take Coraza's security and the trust of our community seriously. If
> you believe you have found a security issue in Coraza or any of its
> components, please responsibly disclose by contacting us. See
> [SECURITY.md](https://github.com/corazawaf/coraza/blob/v2/master/SECURITY.md)
> for details.


We are striving to support an open community for the Coraza Project. We support
our contributors, please don't feel afraid or unsure of submitting feedback or
asking a question.

## Community

* Get in touch via the [OWASP Slack Community](https://owasp.org/slack/invite) (#coraza)
* Monthly Meetings: [Summaries](https://github.com/corazawaf/coraza/issues?q=is%3Aissue+label%3Ameeting)
* Planning: [Github Projects](https://github.com/orgs/corazawaf/projects?type=beta)

## Contributions

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
* You may consider installing a pre-commit hook to automatically run required checks with `go run mage.go precommit`

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

Do you have questions about the source code? Ask any question about how to use Coraza in the community [Discussions](https://github.com/corazawaf/coraza/discussions/categories/q-a).

## Testing

Coraza uses Go's built-in test tool. Examples (run from the repository root):

- `go test -v` or `go run mage.go test`
- `go test -v -race ` use to enable the built-in data race detector
- `go test -run TestDefaultWriters -v ./loggers` run all tests loggers package with name substring `TestDefaultWriters`

- `go run mage.go lint` run code style checks
- `go run mage.go check` run tests and code style checks

- `go run mage.go precommit` install the pre-commit git hook

_________________

The Coraza project is a community effort. We encourage you to pitch in and join the team!

Thanks! :heart: :heart: :heart:

Coraza Team
