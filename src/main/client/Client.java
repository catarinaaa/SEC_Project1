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
			System.out.println(notary.intentionToSell("user1", "good1"));
			System.out.println(notary.intentionToSell("user2", "good1"));
			System.out.println(notary.intentionToSell("user1", "good1"));
			System.out.println(notary.stateOfGood("good1").getUserId() + " " + notary.stateOfGood("good1").getState());
			System.out.println(notary.stateOfGood("good4").getUserId() + " " + notary.stateOfGood("good4").getState());
			
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.out.println("Error locating Notary");
			e.printStackTrace();
			return;
		}
		
		
		
	}
}
