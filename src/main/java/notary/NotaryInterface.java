package main.java.notary;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.Set;

public interface NotaryInterface extends Remote {

	String getNounce(String userId) throws RemoteException;

	Result intentionToSell(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException;

	State stateOfGood(String userId, String cnounce, String goodId) throws RemoteException;

	Result transferGood(String sellerId, String buyerId, String goodId, String cnounce, byte[] signature)
			throws RemoteException;

	String sayHello() throws RemoteException;
}
