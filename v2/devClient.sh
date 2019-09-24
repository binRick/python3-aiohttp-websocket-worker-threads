#!/bin/bash
exec nodemon -w . -e sh,py,j2 -x bash -- -c "sleep 3 && ./client.sh"
