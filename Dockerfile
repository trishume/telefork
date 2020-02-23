FROM rust:1.41

RUN apt-get update
RUN apt-get install rr --yes
RUN apt-get install psmisc htop

VOLUME /usr/src/telefork
WORKDIR /usr/src/telefork
