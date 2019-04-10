#!/bin/bash

echo "Creating folders..."
mkdir classes
mkdir ../Library/classes
mkdir storage

echo "Compiling..."
javac -d ../Library/classes ../Library/src/main/java/pt/ulisboa/tecnico/hdsnotary/library/*.java 
javac -d classes -cp ../Library/classes:lib/pteidlibj.jar src/main/java/pt/ulisboa/tecnico/hdsnotary/server/*.java

echo "Starting Server..."
java -Djava.library.path=/usr/local/lib -Dfile.encoding=UTF-8 -classpath classes:../Library/classes:lib/pteidlibj.jar pt.ulisboa.tecnico.hdsnotary.server.NotaryServer