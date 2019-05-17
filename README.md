# sec2019
Highly Dependable Systems project from IST.

## Creators
Catarina Brás 83439\
Pedro Salgueiro 83542\
Tiago Almeida 83568


## Instructions
Below there are 4 different executions, 1 with normal execution and 3 with simulation of possible byzantine erros
7 terminals should be open for executing the tests and the following commands should be introduced.
To run the Notaries using the citizen card for authentication, change the 2nd argument to true.

Please, run ./clean.sh followed by ./compile.sh to clean all databases before runninng every demo.

Demo 1 - Normal Run
./runRMIRegistry.sh
./runServer.sh Notary1 false
./runServer.sh Notary2 false
./runServer.sh Notary3 false
./runServer.sh Notary4 false

./runClient.sh 1
./runClient.sh 2
./runClient.sh 3


Demo 2 - Read and Write at the same time
Client 2, Bob, will delay writes to some Notaries on intentionToSell every time
./runRMIRegistry.sh
./runServer.sh Notary1 false
./runServer.sh Notary2 false
./runServer.sh Notary3 false
./runServer.sh Notary4 false

./runClient.sh 1
./runClient.sh 2 2
./runClient.sh 3

On Client2, Bob, sell good3 and on Charlie, Client3, check state of good3

Demo 3 - Byzantine Server
./runRMIRegistry.sh
./runServer.sh Notary1 false
./runServer.sh Notary2 false false true
./runServer.sh Notary3 false
./runServer.sh Notary4 false

./runClient.sh 1
./runClient.sh 2
./runClient.sh 3

Every time a read or write operation is executed by the Notary2, it will send a different readId or timestamp

Demo 4 - Byzantine Client
./runRMIRegistry.sh
./runServer.sh Notary1 false
./runServer.sh Notary2 false
./runServer.sh Notary3 false
./runServer.sh Notary4 false

./runClient.sh 1
./runClient.sh 2 4
./runClient.sh 3

Every time Client2, Bob, makes a write or read request, it will send wrong information to one notary