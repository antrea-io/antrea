---
name: antrea-style
description: Antrea repository conventions for Go code, tests, CRD APIs, docs, commit messages and PR descriptions. Load before writing or reviewing any code, doc, commit or PR in the Antrea repository, and before deciding how to shape a helper, a table-driven test, a CRD field or a klog call.
---

# Antrea conventions

These are the conventions the Antrea project follows today, not any one contributor's habits. They
were set over the years mostly by the top committers, and everyone else follows them.

Counts come from the non-generated tree under `pkg/` and `cmd/` as it stands now, and from the most
recent few hundred commits on `main`. They are given wherever a rule is a majority rather than an
absolute, so you can tell a convention from a preference. **When a file you are editing disagrees
with a rule here, follow the file.** Older code holds patterns this document tells you not to write,
because the conventions moved; see `history.md` in this directory for when and why each one moved.

Generated code is never edited by hand. Regenerate with `make codegen` and `make manifest`.

## Go: where a helper goes

A helper is a **package-level function when it is pure**, a **method when it reads receiver
state**, and a **closure only when it must capture a local built earlier in the same function**.
There are 1883 package-level functions and 3558 methods against 165 closures assigned to a
variable, a ratio of about 1 to 33 against package-level helpers.

Do not introduce a closure to remove duplication from a loop body. Write the package-level
function and pass what it needs, even if that means six positional parameters. `addRoutes` and
`addServiceRoute` in `pkg/agent/controller/bgp/controller.go` are the model.

Long positional parameter lists are the accepted norm. `NewNetworkPolicyController` takes 28
parameters. **Do not introduce an option struct or functional options to shorten a constructor**,
add the positional parameter. Past about four parameters, put one per line. Functional options are
sanctioned in tests only, to vary a heavy constructor across table rows, see
`pkg/agent/proxy/proxier_test.go:387-427`.

The one closure idiom worth copying is the immediately invoked closure that scopes a lock, 161
occurrences, `pkg/agent/controller/egress/egress_controller.go:1110`.

## Go: comments

Doc comments sit above the declaration and **start with the identifier name**, 1993 of 2085. Only
38% of functions have one at all, so leaving a small obvious function undocumented is correct.

The comment that matters is the long one explaining **why**, on control flow whose reason is not
visible locally. Nine lines on `updateEndpointsStates` at `pkg/agent/proxy/proxier.go:345`
explaining why the state commit must be last. Six lines inside `NewClient` at
`pkg/agent/route/route_linux.go:336` explaining why the ports are copied and not referenced. Write
these. Do not write comments that restate the signature.

Comments go on their own line above the code, 10284 of them, against 300 trailing `//` comments.
Wrap comments at about 115 columns.

## Go: errors and logging

Use the structured forms only. `klog.InfoS`, `klog.ErrorS`, `klog.V(2).InfoS`. The `Infof` and
`Errorf` forms are residue and must not be added.

- `V(2)` is the per-object event level, `V(4)` the inner loop level. Nothing else is used.
- `ErrorS` messages start with `Failed` or `Error`. `InfoS` messages start with a gerund
  (`Processing`, `Updating`, `Starting`) or a past participle (`Deleted`, `Added`).
- No trailing period, no interpolation into the message. Values go in key-value pairs.
- Keys are lowerCamel for scalars (`nodeName`, `ruleID`, `podIP`) and UpperCamel when the key names
  an API object type (`Pod`, `Service`, `Egress`, `EndpointSlice`). Object values go through
  `klog.KObj` or `klog.KRef`.
- `klog.ErrorS(nil, "Received unexpected object", "obj", obj)` is the idiom for a logic error with
  no error value.
- `loggercheck` is enabled, so key-value pairs must balance.

Wrap errors with `fmt.Errorf("failed to <verb> ...: %w", err)`. 580 uses of `%w` against 226 of
`%v`. Error strings stay lowercase, staticcheck ST1005 is disabled deliberately.

## Go: naming

Spell names out. Collections are named for their contents, never `m`, `s` or `l`. `peerConfigs`,
`antreaInputChainRules`, `nodePortAddresses`. Where a map key needs naming, put the shape in the
name, `memberSetByNode`, `statusPerNode`.

- Receivers are one or two letters, consistent per type. `c` for controllers and clients, `f` for
  features, `p` for the proxier.
- **Struct bool fields take an `Enabled` suffix**, `proxyAllEnabled`, `egressEnabled`. 55 of 265.
- **Bool-returning functions take an `is`, `has`, `should` or `matches` prefix**,
  `hasLocalServingEndpoints`, `isEgressSchedulable`.
- Local bools drop the prefix when already a predicate, `blocked`, `internalLocal`.
- Controller methods follow a fixed vocabulary. `add<Type>`, `update<Type>`, `delete<Type>` for
  informer handlers, `sync<Thing>` for reconcilers, `enqueue<Thing>`, `process<Thing>`.
- Unused handler parameters are `_`, `func (c *Controller) updateEndpointSlice(_, obj interface{})`.
- Use `sets.New[T]` and `ptr.To`. Keep `interface{}` rather than `any` in informer handler
  signatures, 635 to 357.

## Go: shape

Keyed struct literals always, 5919 keyed field lines against 24 positional. One field per line past
about two fields. When a helper exists, let the helper build the literal rather than the caller.

Early return is the default. `else` after a `return` is linted out by revive. In loops use
`continue` rather than nesting. Use `if err := f(); err != nil` when the value is discarded.

Imports are three groups separated by blank lines: stdlib, third party, then `antrea.io/antrea/v2`.
Enforced by goimports with `local-prefixes`. Alias k8s API groups with their version,
`discovery "k8s.io/api/discovery/v1"`, `crdv1b1 ".../crd/v1beta1"`. Fakes get a `fake` or `test`
prefix or suffix, `bgptest`, `ofmock`, `netlinktest`.

Target 120 columns for code, 115 for comments. There is no 80 column rule: 91% of lines are already
under 80 because they are short, not because they were wrapped.

## Go: tests

The table is a slice of an anonymous struct whose first field is `name string`, 779 of about 790.
Iterate `for _, tt := range tests` with `t.Run(tt.name, ...)`. Variable names are `tests` and `tt`.

- Expectation fields use the `expected` prefix, `expectedErr`. Not `want`.
- **`expectedCalls func(mock *XxxMockRecorder)`** is the Antrea way to let a row program gomock, 73
  occurrences. Prefix per mock when a test drives more than one,
  `expectedIPSetCalls`, `expectedNetlinkCalls`.
- `require` for a precondition whose failure makes the rest meaningless, `require.NoError` on
  setup. `assert` for the actual checks. Do not end a subtest with `require`.
- `assert.ElementsMatch` for order-independent slices.
- Helpers: `newFake<Thing>` for a fixture, `generate<Thing>` or `makeTest<Thing>` for object
  builders, `check<Thing>` for shared assertions, lowercase `test<Thing>` for a shared subtest body.
- Fixtures and constructors near the top of the file, pure data builders at the bottom after the
  tests.
- The toolchain is `go.uber.org/mock/gomock`, `stretchr/testify`, and `testing/synctest` for
  time-dependent tests.

When you extend an existing builder to take a new parameter, refactor it into the richer function
and leave the old name as a thin wrapper, so existing callers keep producing identical objects.

## CRD API

**The project uses zero kubebuilder markers.** `grep -rn "+kubebuilder" pkg/apis/` returns nothing.
Validation, defaults, bounds and CEL rules live only in the hand-written CRD YAML under
`build/charts/antrea/crds/`, and the Go doc comment restates them in prose. The only markers are
`// +optional`, `// +genclient` and the deepcopy-gen ones.

Field doc comments start with the Go field name and a verb, `is`, `specifies`, `selects`,
`defines`, `lists`, `configures`. About 2 to 1 against the older article-first form. Phrase ranges
and defaults as `The range of the value is from 1 to 255, and the default value is 1.`

A field is a pointer exactly when the CRD YAML gives it a `default`, or when nil must be told from
the zero value. Required fields are values with a bare json tag, optional fields carry `omitempty`.
Slices and maps are never pointers.

In the CRD YAML, two-space indent, list dashes indented one level under their key, and within a
schema node the order is `type`, `format`, constraints, `required`, then `properties` or `items`.
Integers always carry `format: int32`. `x-kubernetes-validations` goes before `properties`. Comments
appear only to explain a non-obvious constraint. CEL is rare, 7 blocks in 3 of 20 files; most
cross-field validation lives in Go webhooks.

## Documentation

There is no line limit, MD013 is off. Each file picks 80 or 120 and keeps it. Match the file you
are editing. Run `make markdownlint` before pushing.

- One `#` title, then `##` and `###`. Depth 5 is unused.
- If the file has `<!-- toc -->` markers and you add or rename a heading, run `make toc`.
- Introduce a code block with a sentence ending in a colon, a blank line, then a fence with an
  explicit language. Prefer `yaml`, `bash`, `text`.
- Tables are pipe-delimited with a plain `|---|---|` separator, no alignment colons, Title Case
  headers. Footnotes are `<sup>[3]</sup>` in the cell plus a `[3] _italic._` line under the table.
- API fields are backticked code spans in lowerCamelCase exactly as they appear in YAML.
- Cross-doc links are bare relative filenames, `[document](egress.md)`.
- Caveats are a paragraph opening with `**Note**: `.

## Feature gates and the files that move together

A feature gate change is never one file. `pkg/features/antrea_features.go`, the conf template under
`build/charts/antrea/conf/`, the five generated `build/yamls/*.yml`, `docs/feature-gates.md` with
both a table row and a `### Name` section carrying `#### Requirements for this Feature`, the wiring
in `cmd/antrea-agent/agent.go`, and the fixture in
`pkg/agent/apiserver/handlers/featuregates/handler_test.go`.

A new CRD adds `pkg/apis/crd/vX/types.go` and `register.go`, the chart CRD YAML,
`build/yamls/antrea-crds.yml` and the per-platform manifests, the regenerated deepcopy and client,
and a row in `docs/api.md` recording the CRD version and the release it appeared in.

Doc updates ship in the same commit as the code, not as a follow-up.

## Commit messages

Capitalized imperative subject, no trailing period, no conventional-commit prefix. Median 56
characters, keep under 70. The `(#NNNN)` suffix is added by the squash merge, do not write it.

Blank line, then a prose body wrapped at 72 to 89 columns. **Explain what the code did wrong and
why that is wrong before saying what changed.** Two to four paragraphs. Reference a prior commit as
a short hash plus its quoted subject. A bare `Fixes #NNNN` line at the end when the change closes an
issue, or a prose pointer when it does not.

`Signed-off-by:` is mandatory, the DCO check fails without it. Use `git commit -s`.

```
Return the error when adding messages to a bundle fails

AddOFEntriesInBundle discarded the error returned by addMessage and
returned nil instead, so the caller was told the operation succeeded
even though no message had been added to the bundle and no commit had
been sent to OVS. The caller then recorded the entries as installed,
and because no error was surfaced, nothing retried them.

Signed-off-by: Hongliang Liu <hongliang.liu@broadcom.com>
```

## PR descriptions

The body is the commit body, in the same problem-then-change order, with no headings and no
checklists. Headings are the exception, about 3 in 25.

Append material that belongs to the PR and not to git history as final short paragraphs: which
releases are affected, and **why the new test is falsifiable**, in the form "reverting the one line
change makes both of them fail".

Cross-reference other work by PR number in a PR description, and by short hash plus quoted subject
in a commit message.

Cherry-pick PRs are generated, never hand-written.
