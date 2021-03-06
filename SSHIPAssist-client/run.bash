#! /bin/bash

function valid () {
	if [ $? -eq 0 ]; then
	    return true;
	else
	    return false;
	fi
}

rm build/libs/SSHIPAssist-client-all-1.0.jar;
../gradlew fatjar;

if [ valid ]; then
	java -jar build/libs/SSHIPAssist-client-all-1.0.jar "$@";
else
	echo "Skipping remaining commands due to previous error.";
fi
