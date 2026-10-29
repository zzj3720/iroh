# still.fail's iroh

The `stillfail` branch is iroh as still.fail ([AFK-surf/still.fail](https://github.com/AFK-surf/still.fail)) builds it:
upstream's release (`v1.0.3` now) and one commit for each change of ours on top, each marked `ember:` in the source.
still.fail takes the `iroh` crate from here by commit (`[patch.crates-io]` in its `client/Cargo.toml` and
`station/native/mesh/Cargo.toml`).

- A change: a commit here, its tests green (`.github/workflows/stillfail.yml`), then still.fail's pin moved to it.
- A new upstream release: this branch rebased onto its tag.
- A change upstream takes in a release: its commit dropped at the rebase.
