package pt.ulisboa.tecnico.hdsnotary.library;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface UserInterface extends Remote {
	
	String getNounce(String userId, byte[] signature) throws RemoteException;
	
	Boolean buyGood(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException;
}
