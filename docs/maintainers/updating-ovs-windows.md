# Updating the OVS Windows Binaries

Antrea ships a zip archive with OVS binaries for Windows. The binaries are
hosted on the antrea.io website and updated as needed. This file documents the
procedure to upload a new version of the OVS binaries. The archive is served
from AWS S3, and therefore access to the Antrea S3 account is required for this
procedure.

* We assume that you have already built the OVS binaries (if a custom built is
  required), or retrieved them from the official OVS build pipelines. The
  binaries must be built in **Release** mode for acceptable performance.

* Name the zip archive appropriately:
  `ovs-<OVS VERSION>[-antrea.<BUILD NUM>]-win64.zip`
  - the format for `<OVS VERSION>` is `<MAJOR>.<MINOR>.<PATCH>`, with no `v`
    prefix.
  - the `-antrea.<BUILD NUM>` component is optional but must be provided if this
    is not the official build for the referenced OVS version. `<BUILD NUM>`
    starts at 1 and is incremented for every new upload corresponding to that
    OVS version.

* Generate the SHA256 checksum for the archive.
  - place yourself in the directory containing the archive.
  - run `sha256sum -b <NAME>.zip > <NAME>.zip.sha256`, where `<NAME>` is
    determined by the previous step.

* Upload the archive and SHA256 checksum file to the `ovs/` folder in the
  `downloads.antrea.io` S3 bucket. As you upload the files, grant public read
  access to them (you can also do it after the upload with the `Make public`
  action).

* Validate both public links:
  - `https://downloads.antrea.io/ovs/<NAME>.zip`
  - `https://downloads.antrea.io/ovs/<NAME>.zip.sha256`

* Udate the Antrea Windows documentation and helper scripts as needed,
  e.g. `hack/windows/Install-OVS.ps1`.
