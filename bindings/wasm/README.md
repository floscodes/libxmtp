# WASM bindings for the libXMTP rust library

> [!INFO]
> These bindings are not intended to be used directly, use the associated SDK instead.

## Setup

1. Install the [emscripten toolchain](https://emscripten.org/docs/getting_started/downloads.html): `brew install emscripten`. `emscripten` is used to compile from Rust to WebAssembly.
2. Install LLVM: `brew install llvm`, and then follow the instructions to add it to your PATH. Emscripten depends on LLVM's Clang (as opposed to Apple's Clang).

## Useful commands

- `yarn`: Installs all dependencies (required before building)
- `yarn build`: Build a release version of the WASM bindings for the current
  platform
- `yarn lint`: Run cargo clippy and fmt checks
- `yarn format:check`: Check formatting of integration tests
- `yarn typecheck`: Run typecheck on integration tests
- `yarn test`: Run cargo test with `wasm32-unknown-unknown` target
- `yarn test:integration`: Run integration tests using vitest

### macOS commands

These commands require Homebrew and `llvm` to be installed. See above.

- `yarn check:macos`: Run cargo check
- `yarn lint:macos`: Run cargo clippy and fmt checks
- `yarn build:macos`: Build a release version of the WASM bindings
- `yarn test:integration:macos`: Run integration tests using vitest

### macOS aarch64 (Apple Silicon) additional configuration

When building on macOS with aarch64 (Apple Silicon) architecture a build error might occur when trying to use the `clang` compiler which is necessary to build some dependencies. As mentioned above you need to install `llvm` and tell `cargo` to use compiler,
archiver and linker from `llvm` (see the example below).

**Fix:**

- Create a `.cargo` directory in your project root
- In this directory create a `config.toml`file
- Add the following to `config.toml`:

  ```toml
  [target.wasm32-unknown-unknown]
  linker = "/opt/homebrew/opt/llvm/bin/wasm-ld"

  [env]
  CC_wasm32_unknown_unknown = "/opt/homebrew/opt/llvm/bin/clang"
  AR_wasm32_unknown_unknown = "/opt/homebrew/opt/llvm/bin/llvm-ar"
  ```

This should fix the building issues.

# Publishing

To release a new version of the bindings, update the version in `package.json` with the appropriate semver value. Once merged, manually trigger the `Release WASM Bindings` workflow to build and publish the bindings.
