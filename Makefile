build-release:
	cargo build --locked --bins --release
	ln target/release/agnos agnos
	ln target/release/agnos-generate-accounts-keys agnos-generate-accounts-keys