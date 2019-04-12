# sec2019
Highly Dependable Systems project from IST.

## Creators
Catarina Brás 83439\
Pedro Salgueiro 83542\
Tiago Almeida 83568


## Instructions
Below there are 5 different executions, one with normal execution and 4 with simulation of attacks.
4 terminals should be open for executing the tests and the following commands should be introduced.

Please, run ./clean.sh to clean all databases before runninng every test

Simple demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] good1 [Enter]
T3: 1 [Enter]
T3: 4 [Enter] good1 [Enter]
T3: 3 [Enter] good1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]

******************************************************
Replay attack demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runReplayClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] good1 [Enter]
T3: 1 [Enter]
T3: 4 [Enter] good1 [Enter]
T3: 3 [Enter] good1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]

In this test, Alice tries to sell the same good twice

Result: 1st sell succeeds, 2nd fails

*******************************************************
Wrong user attack demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runAuthClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T3: 1 [Enter]
T2: 2 [Enter] good3 [Enter]
T3: 1 [Enter]

In this test, Alice tries to sell a good from another user,
passing as parameters the info of the other user

Result: fail

******************************************************
Man-in-the-middle attack demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runManClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] good1 [Enter]
T3: 2 [Enter] good4 [Enter]
T4: 3 [Enter] good1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]
T4: 1 [Enter]

In this test, Alice is selling good1 and Bob is selling good4, 
when Charlie wants to buy good1, and Alice intercepts the transferGood
call and changes good1 to good4

Result: fail to buy good1 

******************************************************
Server failure demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] good2 [Enter]
T1: [Ctrl-C] ./runServer.sh
T3: 1 [Enter]
T2: 4 [Enter] good1 [Enter]
T3: 4 [Enter] good1 [Enter]
T3: 3 [Enter] good1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]
