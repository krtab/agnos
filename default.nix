{ pkgs ? import <nixpkgs> {}, lib ? pkgs.lib }:

let
  rustPlatform = pkgs.rustPlatform;

  agnos = rustPlatform.buildRustPackage {
    pname = "agnos";
    version = "0.1.0";

    src = lib.fileset.toSource { root = ./.; fileset = lib.fileset.unions [
          ./Cargo.lock
          ./Cargo.toml
          ./LICENSE.txt
          ./README.md
          ./resources/Banner-optimized.png
          ./resources/red-iron.png
          ./src
          ./systemd
    ]; };

    cargoLock = {
      lockFile = ./Cargo.lock;
    };

    nativeBuildInputs = [
      pkgs.pkg-config
    ];

    buildInputs = [
      pkgs.openssl
    ];

    buildPhase = ''
      cargo build --release
    '';

    installPhase = ''
      mkdir -p $out/bin
      cp target/release/agnos $out/bin/
      
      # Install systemd unit and timer
      mkdir -p $out/lib/systemd/system
      cp ${./systemd/agnos.service} $out/lib/systemd/system/
      cp ${./systemd/agnos.timer} $out/lib/systemd/system/
    '';

    meta = with lib; {
      description = "A Rust project with systemd unit and timer files";
      license = licenses.mit;
      maintainers = [ maintainers.krtab ];
    };
  };
in
agnos
