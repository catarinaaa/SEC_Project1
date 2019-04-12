#!/bin/bash

echo "Creating folders..."
mkdir Client/classes
mkdir Server/classes
mkdir Library/classes
mkdir Server/storage

echo "Compiling..."
javac -d Library/classes Library/src/main/java/pt/ulisboa/tecnico/hdsnotary/library/*.java 
javac -d Server/classes -cp Library/classes:Server/lib/pteidlibj.jar Server/src/main/java/pt/ulisboa/tecnico/hdsnotary/server/*.java
javac -d Client/classes -cp Library/classes Client/src/main/java/pt/ulisboa/tecnico/hdsnotary/client/*.java

echo "Starting Server..."
konsole --noclose -e java -Djava.library.path=/usr/local/lib -Dfile.encoding=UTF-8 -classpath Server/classes:Library/classes:Server/lib/pteidlibj.jar pt.ulisboa.tecnico.hdsnotary.server.NotaryServer &
sleep 10
echo "Starting User..."
java -classpath Library/classes:Client/classes pt.ulisboa.tecnico.hdsnotary.client.Client 1