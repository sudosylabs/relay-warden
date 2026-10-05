# Dependency attribution

`upstream/` retains Iroh's MIT/Apache texts and the BSD-3 notice for
Tailscale-derived relay code. Keep these unchanged when updating the adapter.

Most dependency texts come directly from Cargo's unpacked crate sources,
including nested vendored licence and notice files. `dependency-overrides.json`
records version-specific exceptions for packages that omit their licence
files. The source commit is checked against the crate's `.cargo_vcs_info.json`;
a changed version/commit requires a fresh review, not an automatic fallback.

Files in `dependencies/` are unmodified upstream texts from those commits,
except the canonical Apache-2.0 and MIT templates used where no licence file
is present upstream. See the JSON notes for these exceptions. Those templates
do not assign ownership to Relay Warden or replace a missing upstream
copyright attribution. Review these cases before a public release.

`DEPENDENCY_LICENSES.txt` is generated for each archive's target graph and
includes build/test dependencies as well as normal dependencies. The root
`THIRD_PARTY_NOTICES.md` is a broader locked-dependency inventory, not the
licence bundle itself. No automatic compatibility/legal-compliance claim is
made by either file.
