package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.TreeMap;

public interface NotaryInterface extends Remote {

	String getNonce(String userId) throws RemoteException;

	Result intentionToSell(String userId, String goodId, String cnonce, byte[] signature)
		throws RemoteException;

	Result stateOfGood(String userId, String cnonce, String goodId, byte[] signature)
		throws RemoteException;

	Transfer transferGood(String sellerId, String buyerId, String goodId, String cnonce,
		byte[] signature)
		throws RemoteException, IOException, TransferException;

	X509Certificate getCertificate() throws RemoteException;

	TreeMap<String, Boolean> connectToNotary(String userId, String cnonce, X509Certificate userCert,
		byte[] signature) throws RemoteException, InvalidSignatureException;
}
