{
  description = "txcript — Rust toolchain and native build dependencies";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Matches the CI `test` job: stable, plus rustfmt and clippy, plus the
        # wasm32 target the `wasm` job checks against. rust-src is not used by
        # CI but rust-analyzer needs it.
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
          targets = [ "wasm32-unknown-unknown" ];
        };

        # The CI `msrv` job pins this exactly. Keep in lockstep with
        # `rust-version` in Cargo.toml when you bump the toolchain.
        msrv = pkgs.rust-bin.stable."1.96.0".default;

        # Native build inputs, and why each one is here:
        #   cmake, perl — wreq builds BoringSSL from source
        #   pkg-config  — standard -sys crate discovery
        #   clang/llvm  — libclang, for any bindgen in the -sys chain
        # rusqlite uses the `bundled` feature and compiles SQLite from C, so it
        # needs a C compiler but no system libsqlite; stdenv supplies that.
        nativeDeps = with pkgs; [
          pkg-config
          cmake
          perl
          clang
        ];

        darwinDeps = pkgs.lib.optionals pkgs.stdenv.isDarwin
          (with pkgs; [ libiconv ]);

        # The npm package build: `wasm-bindgen-cli` MUST match the
        # `wasm-bindgen` crate version in Cargo.lock (currently 0.2.126) or the
        # generated bindings fail to load. If nixpkgs drifts, pin it with an
        # override rather than letting the versions diverge.
        jsDeps = with pkgs; [
          wasm-bindgen-cli
          nodejs
          bun
        ];

        shellFor = toolchain: extra: pkgs.mkShell {
          packages = [ toolchain ] ++ nativeDeps ++ darwinDeps ++ extra;

          # bindgen, if it appears anywhere in the dependency tree, needs to be
          # told where libclang lives; nixpkgs does not put it on a default
          # search path.
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            echo "txcript dev shell — $(rustc --version)"
          '';
        };
      in
      {
        devShells = {
          # `nix develop` — everything CI needs except the npm packaging step.
          default = shellFor rust [ ];

          # `nix develop .#js` — adds the wasm-bindgen/bun/node toolchain.
          js = shellFor rust jsDeps;

          # `nix develop .#msrv` — reproduces the CI msrv job exactly.
          msrv = shellFor msrv [ ];
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
