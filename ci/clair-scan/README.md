# Antrea Docker Image vulnerability scan

The code in this folder integrates with
[clair-scanner](https://github.com/arminc/clair-scanner), a CLI utility which
uses [Clair](https://github.com/quay/clair) to scan Docker images for
vulnerabilities.

The [run.sh](run.sh) script is meant to be run as a CRON job in CI. It will look
for unusual security vulnerabilities and report them by email.
