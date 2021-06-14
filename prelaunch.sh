#!/bin/bash

sudo tmux new -s spicy_session -d
tmux send-keys -t spicy_session 'sudo ./launch.sh' Enter
tmux attach -t spicy_session

