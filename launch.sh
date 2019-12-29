#!/usr/bin/env bash

NETWORK_NAME="sweet_onions"
DOCKER_OPTS="-it --rm --network $NETWORK_NAME"

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

nb_onion_networks=$(docker network ls |grep -c 'sweet_onions')
if [ $nb_onion_networks -lt 1 ]
then
	info "CREATING DOCKER $NETWORK_NAME NETWORK"
	docker network create $NETWORK_NAME
fi

info "STARTING DIRECTORY" # In $NETWORK_NAME
docker run $DOCKER_OPTS sweet_onions/directory
