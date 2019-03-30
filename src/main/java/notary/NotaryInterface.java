package main.java.notary;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.Set;

public interface NotaryInterface extends Remote {

	String getNounce(String userId) throws RemoteException;
	
	boolean intentionToSell(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException;
	
	State stateOfGood(String goodId) throws RemoteException;
	
	boolean transferGood(String sellerId, String buyerId, String goodId, String cnounce, byte[] signature) throws RemoteException;
	
	String sayHello() throws RemoteException;
}