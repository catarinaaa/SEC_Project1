package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface UserInterface extends Remote {
	
	String getNonce(String userId, byte[] signature) throws RemoteException;
	
	Boolean buyGood(String userId, String goodId, String cnonce, byte[] signature) throws RemoteException, IOException;
}
