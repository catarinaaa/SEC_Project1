package pt.ulisboa.tecnico.hdsnotary.library;

import java.rmi.RemoteException;

public interface UserInterface {
	
	String getNounce(String userId, byte[] signature);
	
	Boolean buyGood(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException;
}
