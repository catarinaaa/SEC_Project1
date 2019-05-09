package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.TreeMap;

import pt.ulisboa.tecnico.hdsnotary.library.InvalidSignatureException;
import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;

public class Client {

	public static void main(String args[]) {

		System.out.println("Initializing Client");

		int PORT = 3000;

		Scanner scanner = new Scanner(System.in);
		System.out.println("************* WELCOME *************");

		User user = null;
		String name = "";

		Registry reg = null;

		try {
			TreeMap<String, NotaryInterface> notaries = null;
			while( (notaries = locateNotaries()) == null) {
				System.out.println("Trying to reconnect in 3 seconds...");
				Thread.sleep(3000);
			}
			
			while (true) {
				if (args.length == 0) {
					System.out.println("Choose one user to create:");
					System.out.println("1 - Alice");
					System.out.println("2 - Bob");
					System.out.println("3 - Charlie");

					while (!scanner.hasNextInt()) {
						scanner.next();
					}
				}
				switch ((args.length > 0) ? Integer.parseInt(args[0]) : scanner.nextInt()) {
					case 1:
						user = new User("Alice", notaries, "Bob", "Charlie", false);
						name = "Alice";
						break;
					case 2:
						user = new User("Bob", notaries, "Alice", "Charlie", false);
						name = "Bob";
						break;
					case 3:
						user = new User("Charlie", notaries, "Alice", "Bob", false);
						name = "Charlie";
						break;
					default:
						System.out.println("Invalid option!");
				}
				if(user != null) break;
			}
			if ((reg = bindUser(PORT, name, user)) != null) {
				System.out.println("Trying to reconnect in 3 seconds...");
				Thread.sleep(3000);
			}
			
			for (String s : reg.list()) {
				System.out.println("Name > " + s);
			}
			
			Boolean exit = false;

			while (!exit) {

				System.out.println("\nChoose one option:");
				System.out.println("1 - List goods owned");
				System.out.println("2 - Sell good");
				System.out.println("3 - Buy good");
				System.out.println("4 - Check state of Good");
				System.out.println("5 - Logout");

				while (!scanner.hasNextInt()) {
					scanner.next();
				}

				switch (scanner.nextInt()) {
					case 1:
						System.out.println("------ PRINT GOODS " + name + " ------");
						user.listGoods();
						break;
					case 2:
						System.out.println(
							"----- INTENTION TO SELL -----\nInput good ID of good you wish to sell:");
						String goodId = scanner.next();
						user.intentionSell(goodId);
						break;
					case 3:
						System.out
							.println("------ BUYING -----\nInput good ID of good you wish to buy:");
						goodId = scanner.next();
						user.buying(goodId);
						break;
					case 4:
						System.out.println(
							"----- STATE OF GOOD -----\nInput good ID of good you wish to check state:");
						goodId = scanner.next();
						user.stateOfGood(goodId);
						break;
					case 5:
						System.out.println("Goodbye!");
						exit = true;
						break;
					default:
						System.out.println("Invalid option!");
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("ERROR locating Notary servers");
		} catch (KeyStoreException e) {
			System.err.println("ERROR creating user, cryptoUtils error");
		} catch (InvalidSignatureException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		finally {
			System.err.println("Exiting!");
			scanner.close();
			System.exit(0);
		}
	}

	public static TreeMap<String, NotaryInterface> locateNotaries() {
		try {
			TreeMap<String, NotaryInterface> list = new TreeMap<>();
			list.put("Notary1", (NotaryInterface) Naming.lookup("//localhost:3000/Notary1"));
			list.put("Notary2", (NotaryInterface) Naming.lookup("//localhost:3000/Notary2"));
			list.put("Notary3", (NotaryInterface) Naming.lookup("//localhost:3000/Notary3"));
			list.put("Notary4", (NotaryInterface) Naming.lookup("//localhost:3000/Notary4"));
			return list;
		} catch(NotBoundException | MalformedURLException |RemoteException e) {
			return null;
		} 
	}
	
	public static Registry bindUser(int port, String name, User user) {
		try {
			Registry reg = LocateRegistry.getRegistry();
			reg = LocateRegistry.getRegistry(port);
			reg.rebind(name, user);
			return reg;
		} catch (RemoteException e) {
			return null;
		}
	}
}