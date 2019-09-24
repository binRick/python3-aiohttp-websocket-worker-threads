#!/bin/bash
exec nodemon -w . -e sh,py,j2 -x bash -- -c "sleep 5 && ./client.sh"
