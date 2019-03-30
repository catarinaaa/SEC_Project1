package main.client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

import main.notary.NotaryInterface;

public class Client {
	public static void main(String args[]) {
		
		System.out.println("Initializing Client");
		
		NotaryInterface notary = null;
		
		try {
			notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");
				
			User u = new User("user1");
			
			u.sell("good3");
			System.out.println("Transfer > " + u.buyGood("user3", "good3"));
			
			
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.out.println("Error locating Notary");
			e.printStackTrace();
			return;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	}
}
