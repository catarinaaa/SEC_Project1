package main.client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

import main.notary.NotaryInterface;

public class Client {
	public static void main(String args[]) {
		
		SecurityManager sm = System.getSecurityManager();
		
		System.out.println("Initializing Client");
		
		NotaryInterface notary = null;
		
		try {
			notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");
			
			System.out.println(notary.sayHello());
			
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.out.println("Error locating Notary");
			e.printStackTrace();
			return;
		}
		
		
		
	}
}
