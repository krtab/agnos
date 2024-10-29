build-release:
	cargo build --locked --bins --release
	strip target/release/agnos
	strip target/release/agnos-generate-accounts-keys
	ln target/release/agnos agnos
	ln target/release/agnos-generate-accounts-keys agnos-generate-accounts-keys