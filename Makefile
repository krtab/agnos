build-release:
	cargo build --locked --bins --release
	strip target/release/agnos
	strip target/release/agnos-generate-accounts-keys
	ln target/release/agnos agnos
	ln target/release/agnos-generate-accounts-keys agnos-generate-accounts-keys

compose: dockers
	$(MAKE) -C test-docker compose

dockers: agnos-docker pebble-docker

agnos-docker:
	docker buildx build . -f test-docker/agnos/Dockerfile -t agnos

pebble-docker:
	docker buildx build test-docker/pebble -f test-docker/pebble/Dockerfile -t pebble