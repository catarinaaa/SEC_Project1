package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

public interface NotaryInterface extends Remote {

    String getNonce(String userId) throws RemoteException;

    Result intentionToSell(String userId, String goodId, int writeTimeStamp, String cnonce, byte[] signature)
            throws RemoteException, InvalidSignatureException;

    Result stateOfGood(String userId, int readID, String cnonce, String goodId, byte[] signature)
            throws RemoteException, StateOfGoodException, InvalidSignatureException;

    Transfer transferGood(String sellerId, String buyerId, String goodId, int writeTimeStamp,
                          String cnonce,
                          byte[] signature)
            throws RemoteException, IOException, TransferException, InvalidSignatureException;

    X509Certificate getCertificateCC() throws RemoteException;

    X509Certificate connectToNotary(String userId, String cnonce, X509Certificate userCert,
                                    byte[] signature) throws RemoteException, InvalidSignatureException;

    Result getGoodsFromUser(String userId, String cnonce, byte[] signature)
            throws RemoteException, InvalidSignatureException;

    void confirmRead(String id, String goodId, int readID, String cnonce, byte[] signMessage) throws RemoteException;

    void echoBroadcast(BroadcastMessage message, String serverID) throws RemoteException;

    void readyBroadcast(BroadcastMessage message, String serverID) throws RemoteException;

	void recoverErrors() throws IOException;

}
