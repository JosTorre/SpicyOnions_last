FROM debian:latest

RUN apt update && apt -y upgrade && \
	apt -y install git python3 python3-pip && \
	git clone https://github.com/MaitreRenard/SweetOnions.git

WORKDIR /SweetOnions/src
