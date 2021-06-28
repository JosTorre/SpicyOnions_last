#!/usr/bin/env bash
#sudo tmux 
#if tmux has-session; then

NETWORK_NAME="spicy_onions"
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
	docker build -t spicy_onions/$lower_name -f docker/$1 .
}


build_container Generic
build_container Directory
build_container Node
build_container Server
build_container Client

nb_onion_networks=$(docker network ls |grep -c 'spicy_onions')
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
tmux split-window -h
tmux split-window -v
tmux split-window -v
tmux split-window -v
tmux split-window -v

# Send all commands
tmux send-keys -t 0 "docker run $DOCKER_OPTS spicy_onions/server" Enter
tmux send-keys -t 1 "docker run $DOCKER_OPTS spicy_onions/node" Enter
tmux send-keys -t 2 "docker run $DOCKER_OPTS spicy_onions/node" Enter
tmux send-keys -t 3 "docker run $DOCKER_OPTS spicy_onions/directory" Enter
tmux send-keys -t 4 "docker run $DOCKER_OPTS spicy_onions/node" Enter
tmux send-keys -t 5 "docker run $DOCKER_OPTS spicy_onions/node" Enter
tmux send-keys -t 6 "docker run $DOCKER_OPTS spicy_onions/client" Enter
tmux send-keys -t 7 "docker run $DOCKER_OPTS spicy_onions/node" Enter
tmux send-keys -t 8 "sh ./src/network_sniffing.sh" Enter

tmux select-layout tiled # Even out all tile
tmux select-pane -t 5 # Go to directory pane

#tmux send-keys -t 6 "docker run $DOCKER_OPTS spicy_onions/client" Enter
#sh ./src/network_sniffing.sh
