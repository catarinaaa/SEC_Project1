package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface NotaryInterface extends Remote {

	String getNounce(String userId) throws RemoteException;

	Result intentionToSell(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException;

	Result stateOfGood(String userId, String cnounce, String goodId, byte[] signature) throws RemoteException;

	Result transferGood(String sellerId, String buyerId, String goodId, String cnounce, byte[] signature)
			throws RemoteException, IOException;

}
