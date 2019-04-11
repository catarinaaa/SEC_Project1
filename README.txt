Simple demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] 2 [Enter]
T3: 1 [Enter]
T3: 4 [Enter] 1 [Enter]
T3: 3 [Enter] 1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]


Replay attack demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runReplayClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] 2 [Enter]
T3: 1 [Enter]
T3: 4 [Enter] 1 [Enter]
T3: 3 [Enter] 1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]


Wrong user attack demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runAuthClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T3: 1 [Enter]
T2: 2 [Enter] good3 [Enter]
T3: 1 [Enter]

Man-in-the-middle attack demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runManClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T4: 2 [Enter] good5 [Enter]
T2: 4 [Enter] good5 [Enter]
T3: 3 [Enter] good1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]


Server failure demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] good2 [Enter]
T1: [Ctrl-C] ./runServer.sh
T3: 1 [Enter]
T3: 4 [Enter] good1 [Enter]
T3: 3 [Enter] good1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]


Client failure demo:

Terminal 1: ./runServer.sh
Terminal 2: ./runClient.sh 1
Terminal 3: ./runClient.sh 2
Terminal 4: ./runClient.sh 3
T2: 1 [Enter]
T2: 2 [Enter] 2 [Enter]
T2: [Ctrl-C] ./runClient.sh 1
T3: 1 [Enter]
T3: 4 [Enter] 1 [Enter]
T3: 3 [Enter] 1 [Enter]
T2: 1 [Enter]
T3: 1 [Enter]
