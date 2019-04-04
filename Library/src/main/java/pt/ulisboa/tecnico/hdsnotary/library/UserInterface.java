package pt.ulisboa.tecnico.hdsnotary.library;

import java.rmi.RemoteException;

public interface UserInterface {
	Boolean buyGood(String userId, String goodId) throws RemoteException;
}
