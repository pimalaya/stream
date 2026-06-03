# Contributing guide

Thank you for investing your time in contributing to the Pimalaya stream project.

## Development

The development environment is managed by [Nix](https://nixos.org/download.html).
Running `nix-shell` will spawn a shell with everything you need to get started with the lib.

If you do not want to use Nix, you can either use [rustup](https://rust-lang.github.io/rustup/index.html):

```
rustup update
```

or install manually the following dependencies:

- [cargo](https://doc.rust-lang.org/cargo/)
- [rustc](https://doc.rust-lang.org/stable/rustc/platform-support.html) (`>= 1.87`)

## Build

```
cargo build
```

## Test

```
cargo test
```

## Commit style

Pimalaya stream follows the [conventional commits specification](https://www.conventionalcommits.org/en/v1.0.0/#summary).
