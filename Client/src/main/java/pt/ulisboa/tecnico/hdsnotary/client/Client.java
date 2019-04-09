package pt.ulisboa.tecnico.hdsnotary.client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class Client {
	public static void main(String args[]) {

		System.out.println("Initializing Client");

		NotaryInterface notary = null;

		try {
			notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");

			User u = new User("Alice", notary);

			u.sell("good2");

			System.out.println("Transfer > " + u.buyGood("Charlie", "good2"));

			
			u.sell("good1");
			
			u.sell("good3");


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
