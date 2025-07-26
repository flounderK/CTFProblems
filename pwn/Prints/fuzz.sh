#!/bin/bash

touch delete_to_stop_fuzzing
while [ -f delete_to_stop_fuzzing ]; do
	dd if=/dev/urandom of=temp bs=1 count=48 2>/dev/null
	cat temp <(echo "quit") | ./prints >/dev/null
	A=$?
	if [ $A != 0 ]; then
		break
	fi
done
