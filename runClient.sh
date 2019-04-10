#!/bin/bash

echo "Creating folders..."
mkdir Client/classes


echo "Compiling..."
javac -d Client/classes -cp Library/classes Client/src/main/java/pt/ulisboa/tecnico/hdsnotary/client/*.java

echo "Starting User..."
java -classpath Library/classes:Client/classes pt.ulisboa.tecnico.hdsnotary.client.Client