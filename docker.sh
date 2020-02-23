#!/bin/sh
docker run --rm --cap-add=SYS_PTRACE --volume "$(pwd):/usr/src/telefork" --interactive --tty telefork:latest bash
