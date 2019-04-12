#!/bin/bash

echo "Creating folders..."
mkdir Client/classes


echo "Compiling..."
javac -d Client/classes -cp Library/classes Client/src/test/java/pt/ulisboa/tecnico/hdsnotary/client/*.java

echo "Starting User..."
if [ "$1" != "" ]; then
    java -classpath Library/classes:Client/classes pt.ulisboa.tecnico.hdsnotary.client.TestAuthClient $1
else
    java -classpath Library/classes:Client/classes pt.ulisboa.tecnico.hdsnotary.client.TestAuthClient
fi