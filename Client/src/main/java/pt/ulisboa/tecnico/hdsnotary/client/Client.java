package pt.ulisboa.tecnico.hdsnotary.client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class Client {
	public static void main(String args[]) {

		System.out.println("Initializing Client");
		
		int PORT = 3000;
		
		NotaryInterface notary = null;

		try {
			notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");

			User u = new User("user1", notary);
			
			Registry reg = LocateRegistry.getRegistry(PORT);
			reg.rebind("Alice", u);
			
			u.sell("good2");
			System.out.println("Transfer > " + u.buyGood("user3", "good2"));
			
			u.sell("good1");
			System.out.println("Transfer > " + u.buyGood("user4", "good1"));
			
			u.sell("good3");
			
			System.out.println("Server ready!");

			System.out.println("Awaiting connections");
			System.out.println("Press enter to shutdown");
			System.in.read();
			System.out.println("Server termindated");
			System.exit(0);

		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.out.println("Error locating Notary");
			e.printStackTrace();
			return;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
