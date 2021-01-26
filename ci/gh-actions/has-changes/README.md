# "Has Changes" Docker Action

This action sets a boolean output (`has_changes`) if the diff (`push` or
`pull_request` event) includes changes outside of a provided list of paths.

## Inputs

The list of paths to exclude. The action will use Bash pattern matching, so
wildcards (`*`) are supported.

## Outputs

### `has_changes`

Whether ('yes' or 'no') the diff includes changes outside of the provided list
of paths.

## Example usage

```yaml
uses: vmware-tanzu/antrea/ci/gh-actions/has-changes@main
with:
  args: docs *.md ci
```

Make sure to checkout the repo first.
