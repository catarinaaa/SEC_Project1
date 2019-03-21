package main.notary;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface NotaryInterface extends Remote {

	boolean intentionToSell(String userId, String goodId) throws RemoteException;
	
	boolean stateOfGood(String goodId) throws RemoteException;
	
	boolean transferGood(String buyerId, String goodId) throws RemoteException;
	
	String sayHello() throws RemoteException;
}
