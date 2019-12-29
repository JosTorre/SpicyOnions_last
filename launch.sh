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

# Create layout
tmux split-window -h
tmux split-window -v
tmux split-window -v
tmux select-pane -t 0
tmux split-window -v
tmux split-window -v

# Send all commands
tmux send-keys -t 1 "docker run $DOCKER_OPTS sweet_onions/node" Enter
tmux send-keys -t 2 "docker run $DOCKER_OPTS sweet_onions/server" Enter
tmux send-keys -t 3 "docker run $DOCKER_OPTS sweet_onions/node" Enter
tmux send-keys -t 4 "docker run $DOCKER_OPTS sweet_onions/directory" Enter
tmux send-keys -t 5 "docker run $DOCKER_OPTS sweet_onions/node" Enter

tmux select-layout tiled # Even out all tile
tmux select-pane -t 0 # Go back to first panel
