#!/usr/bin/env bash

DOCKER_OPTS="-it --rm --network host"

# $1 : The info to print
info() {
	printf '\n\e[1;32m--------------------------------\n'
	printf '[INFO]	%s\n' "$1"
	printf -- "--------------------------------\e[m\n\n"
}

# $1 : Dockerfile's name in "docker" dir in PascalCase
build_container() {
	lower_name=$(echo "$1" |tr "[:upper:]" "[:lower:]")
	upper_name=$(echo "$1" |tr "[:lower:]" "[:upper:]")

	info "BUILDING $upper_name CONTAINER"
	docker build -t sweet_onions/$lower_name -f docker/$1 .
}


build_container Generic
build_container Directory
build_container Node
build_container Server

info "STARTING DIRECTORY"
docker run $DOCKER_OPTS sweet_onions/directory
