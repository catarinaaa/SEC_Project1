package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStoreException;
import java.util.Scanner;

import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;

public class Client {
	public static void main(String args[]) {

		System.out.println("Initializing Client");

		int PORT = 3001;

		Scanner scanner = new Scanner(System.in);
		System.out.println("Welcome");

		User user = null;
        String name = "";
        
        Registry reg = null;
        
		try {

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
                        user = new User("Alice", notary, "Bob", "Charlie");
                        name = "Alice";
                        user.addGood("good1", false);
                        user.addGood("good2", false);
                        break;
                    case 2:
                        user = new User("Bob", notary, "Alice", "Charlie");
                        name = "Bob";
                        user.addGood("good3", false);
                        user.addGood("good4", false);
                        break;
                    case 3:
                        user = new User("Charlie", notary, "Alice", "Bob");
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

                System.out.println("Choose one option:");
                System.out.println("1 - List goods owned");
                System.out.println("2 - Sell good");
                System.out.println("3 - Buy good");
                System.out.println("4 - Check state of Good");
                System.out.println("5 - Logout");

                while(!scanner.hasNextInt())
                    scanner.next();

                switch (scanner.nextInt()) {
                    case 1:
                    	System.out.println("Printing list of goods owned by " + name);
                        user.listGoods();
                        break;
                    case 2:
                    	System.out.println("Input good ID of good you wish to sell");
                    	String goodId = scanner.next();
                    	user.intentionSell(goodId);
                    	break;
                    case 3:
                    	System.out.println("Input good ID of good you wish to buy");
                    	goodId = scanner.next();
                    	user.buying(goodId);
                    	break;
                    case 4:
                    	System.out.println("Input good ID of good you wish to check state");
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
            

//            user.intentionSell("good2");
//            System.out.println("Transfer > " + user.buyGood("user3", "good2"));
//
//            user.intentionSell("good1");
//            System.out.println("Transfer > " + user.buyGood("user4", "good1"));
//
//            user.intentionSell("good3");
//            
//            System.out.println("Testing state of good");
//            user.stateOfGood("good2");
//
//            System.out.println("Client server ready!");
//
//            System.out.println("Awaiting connections");
//            System.out.println("Press enter to shutdown");
//            System.in.read();
//            System.out.println("Client server terminated");
//            System.exit(0);

        
		} catch (NotBoundException | IOException e) {
            System.out.println("ERROR locating Notary\n Exiting!");
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