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
			
			System.out.println(notary.sayHello());
//			System.out.println(notary.intentionToSell("user1", "good1"));
//			System.out.println(notary.intentionToSell("user2", "good4"));
//			System.out.println(notary.intentionToSell("user1", "good1"));
//			System.out.println(notary.stateOfGood("good1").getUserId() + " " + notary.stateOfGood("good1").getState());
//			System.out.println(notary.stateOfGood("good4").getUserId() + " " + notary.stateOfGood("good4").getState());
//			
//			System.out.println(notary.transferGood("user2", "user1", "good4"));
//			System.out.println(notary.stateOfGood("good1").getUserId() + " " + notary.stateOfGood("good1").getState());
			
			//System.out.println(notary.intentionToSell("user1", "good1"));
			//System.out.println(notary.transferGood("user1", "user3", "good1"));
			
			User u = new User("user1");
			
			u.sell("good1");
			System.out.println("Transfer > " + u.buyGood("user2", "good1"));
			
			
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
