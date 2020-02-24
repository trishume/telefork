FROM rust:1.41

RUN apt-get update
RUN apt-get install rr --yes
RUN apt-get install psmisc htop
RUN rustup component add rust-src

RUN mkdir -p /Users/tristan/Box/Dev/Projects
RUN ln -s /usr/src/telefork /Users/tristan/Box/Dev/Projects/telefork

VOLUME /usr/src/telefork
WORKDIR /usr/src/telefork
