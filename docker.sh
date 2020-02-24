#!/bin/sh
{
docker run --rm --cap-add=SYS_PTRACE --volume "$(pwd):/usr/src/telefork" --interactive --name telefork --tty telefork:latest bash
}
