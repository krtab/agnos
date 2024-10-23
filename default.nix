{ pkgs ? import <nixpkgs> {}, lib ? pkgs.lib }:

let
  rustPlatform = pkgs.rustPlatform;

  agnos = rustPlatform.buildRustPackage rec {
    pname = "agnos";
    version = "0.1.0";

    src = pkgs.fetchFromGitHub {
      owner = "krtab";
      repo = "agnos";
      rev = "v0.1.0-beta.4";
      sha256 = "sha256-ZEW+OdGliREg8mA0nIn8wt908ASUSa1T1LeC7I78CBU=";
    };

    cargoSha256 = "sha256-AYvRbabzGcXZgIe53aAdEZmS7Yag/Kv8eetLw/x/v1Y=";

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
