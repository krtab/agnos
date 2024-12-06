{ pkgs ? import <nixpkgs> {}}:

let 
  inherit (pkgs) lib;
  pebble_cert = ./pebble/cert.pem;
  pebble_priv_key = ./pebble/key.pem;
  pebble_config = pkgs.writeTextFile {
    name = "pebble-config.json";
    text = builtins.toJSON
            { pebble = {
                certificate = pebble_cert;
                privateKey = pebble_priv_key;
                listenAddress =  "0.0.0.0:14000";
                httpPort= 5002;
                tlsPort= 5001;
              };
            };
  };
  wait_for_it = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/vishnubob/wait-for-it/81b1373f17855a4dc21156cfe1694c31d7d1792e/wait-for-it.sh";
    hash = "sha256-t6BPON4eUedFXs9jFRyMfkBb0tRaLU4W9kGdtzehJdY=";
  };
  agnos_config = ./agnos/config_test.toml;
  test-script = pkgs.writeShellScriptBin "agnos-test-script" 
  ''
    set -xve
    trap "trap - SIGTERM; [ -n \"$(jobs -p)\" ] && kill -- -$$" SIGINT SIGTERM EXIT
    ${pkgs.pebble}/bin/pebble -config ${pebble_config} -strict -dnsserver 127.0.0.1:8053 &
    export CARGO_TARGET_DIR=target_nix_test
    ${pkgs.cargo}/bin/cargo build --release
    OLDWORKDIR=$(pwd)
    WORKDIR=$(mktemp -p target_nix_test -d)
    cd $WORKDIR
    $OLDWORKDIR/$CARGO_TARGET_DIR/release/agnos-generate-accounts-keys --key-size 2048 --no-confirm ${agnos_config}
    bash ${wait_for_it} -t 0 127.0.0.1:14000
    $OLDWORKDIR/$CARGO_TARGET_DIR/release/agnos --debug --acme-url https://127.0.0.1:14000/dir --acme-serv-ca ${pebble_cert} ${agnos_config}
    # Purposefully duplicated to test renewal
    $OLDWORKDIR/$CARGO_TARGET_DIR/release/agnos --debug --acme-url https://127.0.0.1:14000/dir --acme-serv-ca ${pebble_cert} ${agnos_config}
    cd $OLDWORKDIR
    rm -rf $WORKDIR
  '';
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ killall rustc cargo gcc rustfmt clippy pebble pkg-config openssl mktemp];

  # Certain Rust tools won't work without this
  # This can also be fixed by using oxalica/rust-overlay and specifying the rust-src extension
  # See https://discourse.nixos.org/t/rust-src-not-found-and-other-misadventures-of-developing-rust-on-nixos/11570/3?u=samuela. for more details.
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

   shellHook = ''
      export PATH=${test-script}/bin:$PATH
  '';

}