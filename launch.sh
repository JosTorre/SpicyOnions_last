#!/usr/bin/env bash

info() {
	printf '\n\e[1;32m--------------------------------\n'
	printf '[INFO]	%s\n' "$1"
	printf -- "--------------------------------\e[m\n\n"
}

info "BUILDING DIRECTORY CONTAINER"
docker build -t sweet_onions/directory	-f docker/Directory .

info "BUILDING NODE CONTAINER"
docker build -t sweet_onions/node		-f docker/Node .

info "BUILDING SERVER CONTAINER"
docker build -t sweet_onions/server		-f docker/Server .

info "STARTING DIRECTORY"
docker run -it --rm --network host sweet_onions/directory
