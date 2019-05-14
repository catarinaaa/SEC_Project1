echo "Creating folders..."
mkdir Server/classes
mkdir Library/classes
mkdir Server/storage
mkdir Client/classes

echo "Compiling..."
javac -d Library/classes Library/src/main/java/pt/ulisboa/tecnico/hdsnotary/library/*.java 
javac -d Server/classes -cp Library/classes:Server/lib/pteidlibj.jar Server/src/main/java/pt/ulisboa/tecnico/hdsnotary/server/*.java
javac -d Client/classes -cp Library/classes Client/src/main/java/pt/ulisboa/tecnico/hdsnotary/client/*.java
