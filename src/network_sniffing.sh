#!/bin/bash

sudo tshark -T fields -e data -w ./src/sniffings/aufnahme_network.pcapng &
sudo tshark -P -V -x 
