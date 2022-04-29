# OSS License Scanner for Antrea Binaries

The code in this folder integrates with
[lichen](https://github.com/uw-labs/lichen), a command-line tool that scans
compiled Go binaries and outputs all their dependencies with their respective
licenses. Lichen is heavily inspired from
[golicense](https://github.com/mitchellh/golicense). Antrea originally used
golicense, but the project is no longer actively maintained and does not support
Windows binaries. Unlike golicense, lichen does not query the Github API;
therefore not requiring an API token and avoiding API rate-limiting issues.

The [run.sh](run.sh) script is meant to be run as a CI job, but can also be run
locally:

```bash
./ci/golicense/run.sh <path to Antrea binaries directory> <output directory for generated reports>
```

## Supported OSS Licenses

For a list of the OSS licenses accepted or rejected for Antrea dependencies,
please see [conf.yml](conf.yml). These lists are not comprehensive and do not
include all possible OSS licenses - however, they do include the most popular
ones. If a patch introduces a new dependency, and the license for that
dependency is listed in "deny", the patch will not be merged. If the license is
neither listed in "deny" nor explicitly listed in "allow", the patch cannot be
merged until project maintainers decide whether the license is acceptable for
the project. [Permissive
licenses](https://en.wikipedia.org/wiki/Permissive_software_license)
which are business-friendly are usually accepted, while [copyleft
licenses](https://en.wikipedia.org/wiki/Copyleft) are not. This is to ensure
that Antrea can easily be used in commercial derivative works.

## Lichen: Binary-based Analysis vs Source-based Analysis

We chose lichen, which uses binary-based dependency analysis, for two reasons:

* It works very well, and there is no source-based analysis alternative which is
  as popular and as easy to use. If we find one, we would consider running it as
  well.
* Binary-based analysis avoids "false positives" by ensuring that all the
  reported dependencies are actually used in the distributed binary assets. It
  is possible for a dependency to be included in the go.mod file, but only used
  in tests or code examples.
