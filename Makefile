build-release:
	cargo build --locked --bins --release
	strip target/release/agnos
	strip target/release/agnos-generate-accounts-keys
	ln target/release/agnos agnos
	ln target/release/agnos-generate-accounts-keys agnos-generate-accounts-keys

compose: dockers
	$(MAKE) -C test-docker compose

dockers: agnos-docker pebble-docker

agnos-docker: buildx-create
	docker buildx build . -f test-docker/agnos/Dockerfile -t agnos

bind9-docker: buildx-create
	docker buildx build test-docker/bind9 -f test-docker/bind9/Dockerfile -t bind9

pebble-docker: buildx-create
	docker buildx build test-docker/pebble -f test-docker/pebble/Dockerfile -t pebble

buildx-create:
	