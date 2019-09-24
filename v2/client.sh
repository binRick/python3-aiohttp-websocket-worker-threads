#!/bin/bash
INSTALL="1"
cd $(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
URI="http://localhost:50009"
C="curl -sk"
set -e
eval $C $URI/tests/cache/get/server_id | grep Cache=None
eval $C $URI/tests/cache/set/server_id/12345 | grep Set
eval $C $URI/tests/cache/get/server_id|grep Cache=12345
