package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStoreException;
import java.util.Scanner;

import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;

public class TestReplayClient {
	public static void main(String args[]) {

		System.out.println("Initializing Client");

		int PORT = 3000;

		Scanner scanner = new Scanner(System.in);
		System.out.println("************* WELCOME *************");

		UserReplay user = null;
        String name = "";
        
        Registry reg = null;
        
		try {
			
			reg = LocateRegistry.getRegistry(PORT);
			
			for(String s : reg.list()) {
				System.out.println("Name > " + s);
			}

            NotaryInterface notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");

            while (true) {
            	if(args.length ==0) {
	                System.out.println("Choose one user to create:");
	                System.out.println("1 - Alice");
	                System.out.println("2 - Bob");
	                System.out.println("3 - Carlos");
            	

                while(!scanner.hasNextInt())
                    scanner.next();
            	}
                switch ((args.length > 0) ? Integer.parseInt(args[0]) : scanner.nextInt()) {
                    case 1:
                        user = new UserReplay("Alice", notary, "Bob", "Charlie");
                        name = "Alice";
                        user.addGood("good1", false);
                        user.addGood("good2", false);
                        break;
                    case 2:
                        user = new UserReplay("Bob", notary, "Alice", "Charlie");
                        name = "Bob";
                        user.addGood("good3", false);
                        user.addGood("good4", false);
                        break;
                    case 3:
                        user = new UserReplay("Charlie", notary, "Alice", "Bob");
                        name = "Charlie";
                        user.addGood("good5", false);
                        user.addGood("good6", false);
                        break;
                    default:
                        System.out.println("Invalid option!");
                }

                if(user!= null) {
                	reg = LocateRegistry.getRegistry(PORT);
    	            reg.rebind(name, user);
                	break;
                }
	            
            }
            
            Boolean exit = true;
            
            while(exit) {

                System.out.println("\nChoose one option:");
                System.out.println("1 - List goods owned");
                System.out.println("2 - Sell good");
                System.out.println("3 - Buy good");
                System.out.println("4 - Check state of Good");
                System.out.println("5 - Logout");

                while(!scanner.hasNextInt())
                    scanner.next();

                switch (scanner.nextInt()) {
                    case 1:
                    	System.out.println("------ PRINT GOODS " + name + " ------");
                        user.listGoods();
                        break;
                    case 2:
                    	System.out.println("------ INTENTION TO SELL ------\nInput good ID of good you wish to sell:");
                    	String goodId = scanner.next();
                    	user.intentionSell(goodId);
                    	break;
                    case 3:
                    	System.out.println("------ BUY GOOD ------\nInput good ID of good you wish to buy:");
                    	goodId = scanner.next();
                    	user.buying(goodId);
                    	break;
                    case 4:
                    	System.out.println("------ GET STATE OF GOOD ------\nInput good ID of good you wish to check state:");
                    	goodId = scanner.next();
                    	user.stateOfGood(goodId);
                    	break;
                    case 5:
                    	System.out.println("Goodbye!");
                    	exit = false;
                    	break;
                    default:
                    	System.out.println("Invalid option!");
                }
            }
           
        
		} catch (NotBoundException | IOException e) {
            System.out.println("ERROR locating Notary\n Exiting!");
            e.printStackTrace();
            scanner.close();
            return;
	    } catch (KeyStoreException e) {
	    	System.err.println("ERROR creating user, cryptoUtils error");
	    	scanner.close();
	    	return;
	    }
		
		 scanner.close();
         System.exit(0);
	}
}