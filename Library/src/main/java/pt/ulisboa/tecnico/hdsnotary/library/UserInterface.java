package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

public interface UserInterface extends Remote {
	
	String getNonce(String userId, byte[] signature) throws RemoteException;
	
	Result transferGood(String userId, String goodId, String cnonce, byte[] signature) throws RemoteException, IOException, TransferException, InvalidSignatureException;

	X509Certificate getCertificate() throws RemoteException;
	
	void connectUser(String id, X509Certificate cert) throws RemoteException;

	void updateValue(String notaryId, Result result, String nonce, byte[] signature) throws RemoteException;
}
