#!/bin/bash
exec nodemon -w . -e sh,py,j2 -x ./server.sh
