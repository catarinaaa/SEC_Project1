#!/bin/bash

echo "Creating folders..."
mkdir classes

echo "Compiling..."
javac -d classes -cp ../Library/classes src/main/java/pt/ulisboa/tecnico/hdsnotary/client/*.java

echo "Starting User..."
java -classpath ../Library/classes:classes pt.ulisboa.tecnico.hdsnotary.client.Client