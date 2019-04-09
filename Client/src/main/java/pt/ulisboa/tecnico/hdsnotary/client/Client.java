package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class Client {
	public static void main(String args[]) {

		System.out.println("Initializing Client");

		int PORT = 3000;

		Scanner scanner = new Scanner(System.in);
		System.out.println("Welcome");
		int option;

		User user = null;
        String name = "";
		try {
            NotaryInterface notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");

            while (true) {

                System.out.println("Choose one user to create:");
                System.out.println("1 - Alice");
                System.out.println("2 - Bob");
                System.out.println("3 - Carlos");


                while(!scanner.hasNextInt())
                    scanner.next();

                switch (scanner.nextInt()) {
                    case 1:
                        user = new User("user1", notary, "Bob", "Charlie");
                        name = "Alice";
                        break;
                    case 2:
                        user = new User("user2", notary, "Alice", "Charlie");
                        name = "Bob";
                        break;
                    case 3:
                        user = new User("user3", notary, "Alice", "Bob");
                        name = "Charlie";
                        break;
                    default:
                        System.out.println("Invalid option!");
                }

                if(user!= null) break;
            }

            Registry reg = LocateRegistry.getRegistry(PORT);
            reg.rebind(name, user);

//            while(true) {
//
//                System.out.println("Choose one option:");
//                System.out.println("1 - List goods owned");
//                System.out.println("2 - Sell good");
//                System.out.println("3 - Buy good");
//
//                while(!scanner.hasNextInt())
//                    scanner.next();
//
//                switch (scanner.nextInt()) {
//                    case 1:
//                        user.listGoods();
//                }
//
//
//            }





            user.intentionSell("good2");
            System.out.println("Transfer > " + user.buyGood("user3", "good2"));

            user.intentionSell("good1");
            System.out.println("Transfer > " + user.buyGood("user4", "good1"));

            user.intentionSell("good3");
            
            System.out.println("Testing state of good");
            user.stateOfGood("good2");

            System.out.println("Client server ready!");

            System.out.println("Awaiting connections");
            System.out.println("Press enter to shutdown");
            System.in.read();
            System.out.println("Client server termindated");
            System.exit(0);

        }
		catch (NotBoundException | IOException | NoSuchAlgorithmException e) {
            System.out.println("Error locating Notary");
            e.printStackTrace();
            return;
	    }

	}
}
