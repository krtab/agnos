compose: dockers
	$(MAKE) -C test-docker compose

dockers: agnos-docker pebble-docker

agnos-docker:
	sudo docker build . -f test-docker/agnos/Dockerfile -t agnos

bind9-docker:
	docker build test-docker/bind9 -f test-docker/bind9/Dockerfile -t bind9

pebble-docker:
	docker build test-docker/pebble -f test-docker/pebble/Dockerfile -t pebble