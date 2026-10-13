# The `txcript` CLI — the tool a person installs.
#
# Separate from package.nix because the two have genuinely different build
# needs. The service links nothing but its own closure; the CLI pulls the
# browser-compatible HTTPS transport the live web stores use, which builds
# BoringSSL from source, and a bundled SQLite for the database-backed stores.
{
  lib,
  rustPlatform,
  stdenv,
  pkg-config,
  cmake,
  perl,
  clang,
  llvmPackages,
  libiconv,
  git,
  # `share_s3` adds the AWS client, for publishing straight to a bucket with
  # no service in the path. Off by default: a build that talks to a share
  # service does not need it, and it is a large dependency tree to audit.
  features ? [ ],
}:

rustPlatform.buildRustPackage {
  pname = "txcript";
  version = "0.14.4";

  src = lib.cleanSourceWith {
    src = ../.;
    # Keep the store path stable across edits to things the build ignores.
    filter =
      path: type:
      let
        name = baseNameOf path;
      in
      !(builtins.elem name [
        "target"
        "result"
        "node_modules"
        "build"
        "pkg"
        ".git"
      ]);
  };

  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "-p"
    "txcript-cli"
  ];
  buildFeatures = features;

  nativeBuildInputs = [
    pkg-config
    # wreq builds BoringSSL from source.
    cmake
    perl
    # libclang, for bindgen anywhere in the -sys chain.
    clang
    # boring-sys patches its vendored BoringSSL through `git init` + `git
    # apply`, so the build fails without a git on PATH.
    git
  ];

  buildInputs = lib.optionals stdenv.hostPlatform.isDarwin [ libiconv ];

  # nixpkgs does not put libclang on a default search path, and bindgen will
  # not find it on its own.
  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

  # The suite runs in CI and in the dev shell. Repeating it inside every
  # package build buys nothing and costs minutes.
  doCheck = false;

  meta = {
    description = "Convert coding-agent session transcripts between harness formats";
    homepage = "https://github.com/skillsynchq/txcript";
    license = lib.licenses.asl20;
    mainProgram = "txcript";
    platforms = lib.platforms.unix;
  };
}
