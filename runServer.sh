#!/bin/bash

echo "Creating folders..."
mkdir Server/classes
mkdir Library/classes
mkdir Server/storage

export CLASSPATH="/home/pedro/SEC/SEC_Project1/Server/classes/:/home/pedro/SEC/SEC_Project1/Library/classes:./"

echo "Compiling..."
javac -d Library/classes Library/src/main/java/pt/ulisboa/tecnico/hdsnotary/library/*.java 
javac -d Server/classes -cp Library/classes:Server/lib/pteidlibj.jar Server/src/main/java/pt/ulisboa/tecnico/hdsnotary/server/*.java

echo "Arguments..."
echo "Notary ID = " $1
echo "Use CC = " $2

echo "Starting Server..."
java -Djava.library.path=/usr/local/lib -Dfile.encoding=UTF-8 -classpath Server/classes:Library/classes:Server/lib/pteidlibj.jar pt.ulisboa.tecnico.hdsnotary.server.NotaryServer $1 $2