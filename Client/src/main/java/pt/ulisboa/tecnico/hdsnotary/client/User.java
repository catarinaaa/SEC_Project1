package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.ConnectException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.*;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class User extends UnicastRemoteObject implements UserInterface {

    private static final long serialVersionUID = 1L;

    private static final long TIMEOUT = 15;
    private static final int NUM_NOTARIES = 4;
    private static final int NUM_FAULTS = 1;

    private static final String[] NOTARY_LIST = new String[]{"Notary1", "Notary2", "Notary3", "Notary4"};
    private static final String NOTARY_CC = "CertCC";

    private final String id;
    private final String user2;
    private final String user3;
    private final Boolean verifyCC;
    private UserInterface remoteUser2 = null;
    private UserInterface remoteUser3 = null;
    // List of all goods possessed
    private Map<String, Good> goods;

    // List of timestamps per good
    private Map<String, Integer> writeTimeStamps;

    // Instance of remote Notary Object
    private TreeMap<String, NotaryInterface> notaryServers;
    private TreeMap<String, UserInterface> remoteUsers = new TreeMap<String,UserInterface>();

    private String keysPath; // KeyStore location
    private String password; // KeyStore password

    CryptoUtilities cryptoUtils;

    private Map<String, String> nonceList = new HashMap<>();

    private ExecutorService service = Executors.newFixedThreadPool(4);

    public User(String id, TreeMap<String, NotaryInterface> notaryServers,
                String user2, String user3,
                Boolean verifyCC)
            throws RemoteException, KeyStoreException, InvalidSignatureException {

        this.id = id;
        this.notaryServers = notaryServers;
        this.user2 = user2;
        this.user3 = user3;
        this.verifyCC = verifyCC;

        this.keysPath = "Client/storage/" + id + ".p12";
        this.password = id + "1234";

        cryptoUtils = new CryptoUtilities(this.id, this.keysPath, this.password);

        System.out.println("Initializing user " + id);

        connectToNotary();

        getGoodFromUser();

        connectToUsers();

    }

    private void connectToUsers() {
		lookUpUsers();
		try {
			for(Map.Entry<String, UserInterface> e : remoteUsers.entrySet()) {
				cryptoUtils.addCertToList(e.getKey(), e.getValue().getCertificate());
				e.getValue().connectUser(this.id, getCertificate());
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

    /*
     * Function to obtain goods owned by the user
     */
    private void connectToNotary() throws RemoteException, InvalidSignatureException {
        // TODO verify signatures
        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);

            String cnonce = cryptoUtils.generateCNonce();
            String toSign = notary.getNonce(this.id) + cnonce + this.id;
            X509Certificate res = null;
			res = notary
					.connectToNotary(this.id, cnonce, cryptoUtils.getStoredCert(), cryptoUtils.signMessage(toSign));

			cryptoUtils.addCertToList(notaryID, res);
            System.out.println("Response");
        }
    }

    public void getGoodFromUser() throws RemoteException {
        TreeMap<String, Good> map = null;

        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);
            //send signed message
            String cnonce = cryptoUtils.generateCNonce();
            String toSign = notary.getNonce(this.id) + cnonce + this.id;
            Result res = null;
            try {
                res = notary.getGoodsFromUser(this.id, cnonce, cryptoUtils.signMessage(toSign));
            } catch (InvalidSignatureException e) {
                e.getMessage();
            } 

            //verify received message
            String toVerify = toSign + res.getContent().hashCode();
            if (!cryptoUtils.verifySignature(notaryID, toVerify, res.getSignature())) {
                System.err.println("ERROR: Signature could not be verified");
            }
            map = (TreeMap<String, Good>) res.getContent();
        }
        System.out.println("Goods owned:");
        for (String s : map.keySet()) {
            System.out.println("> " + s);
        }
        goods = map;
    }

    public String getUser2() {
        return user2;
    }

    public String getUser3() {
        return user3;
    }

    public String getId() {
        return id;
    }

    public Map<String, Good> getGoods() {
        return goods;
    }

    @Override
	public void connectUser(String id, X509Certificate cert) throws RemoteException  {
		cryptoUtils.addCertToList(id, cert);
	}
	
	@Override
	public X509Certificate getCertificate() throws RemoteException {
		return cryptoUtils.getStoredCert();
	}


    /*
     * Function to obtain a nonce for communication
     * Invoked before executing any other method
     */
    @Override
    public String getNonce(String userId, byte[] signature) {

        String nonce = cryptoUtils.generateCNonce();
        nonceList.put(userId, nonce);
        return nonce;
    }

    /*
     * Invoked when another user is buying a good that this user owns
     */
    @Override
    public Transfer buyGood(String userId, String goodId, String cnonce, byte[] signature)
            throws TransferException {

        try {
            Transfer result = null;
            String lastNotary = null;
            for (String notaryID : notaryServers.keySet()) {
                NotaryInterface notary = notaryServers.get(notaryID);

                String toVerify = nonceList.get(userId) + cnonce + userId + goodId;

                if (!cryptoUtils.verifySignature(userId, toVerify, signature)) {
                    throw new TransferException("Error");
                }

                String nonceToNotary = cryptoUtils.generateCNonce();
                String data = notary.getNonce(this.id) + nonceToNotary + this.id + userId + goodId;

                result = notary.transferGood(this.getId(), userId, goodId, nonceToNotary,
                        cryptoUtils.signMessage(data));

                lastNotary = notaryID;
            }

            String transferVerify =
                    result.getId() + result.getBuyerId() + result.getSellerId() + result.getGood().getGoodId();

            if (!verifyCC || cryptoUtils
                    .verifySignature(NOTARY_CC, transferVerify, result.getNotarySignature(),
                            notaryServers.get(lastNotary).getCertificateCC())) {
                System.out.println("CC Signature verified! Notary confirmed buy good");
                goods.remove(goodId);
                return result;
            } else {
                System.err.println("ERROR: CC Signature does not verify");
                throw new TransferException("Error");
            }
        } catch (IOException e) {
            rebind();
            return buyGood(userId, goodId, cnonce, signature);
        }
    }

    /*
     * Invoked when interacting with the users
     */
    public boolean buying(String goodId) {
        try {
            Result stateOfGood = stateOfGood(goodId);
            if (stateOfGood == null || false == (Boolean)stateOfGood.getContent()) {
                System.out.println("ERROR: Buying was not possible!");
                System.out.println("------------------");
                return false;
            } else {
                String seller = stateOfGood.getUserId();
                
                //reconnect to users if one is missing
                if(!remoteUsers.containsKey(seller))
                	connectToUsers();
                
                Transfer result;
                String nonce = remoteUsers.get(seller).getNonce(this.id, cryptoUtils.signMessage(this.id));
                String cnonce = cryptoUtils.generateCNonce();
                nonceList.put(seller, cnonce);
                String toSign = nonce + cnonce + this.id + goodId;
                result = remoteUsers.get(seller)
                        .buyGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
                goods.put(goodId, result.getGood());
                
                /*
                if (seller.equals(user2) && remoteUser2 != null) {
                    if (!cryptoUtils.containsCert(user2)) // TODO
						cryptoUtils.addCertToList(user2, remoteUser2.getCertificate());
                    String nonce = remoteUser2.getNonce(this.id, cryptoUtils.signMessage(this.id));
                    String cnonce = cryptoUtils.generateCNonce();
                    nonceList.put(user2, cnonce);
                    String toSign = nonce + cnonce + this.id + goodId;
                    result = remoteUser2
                            .buyGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
                    goods.put(goodId, result.getGood());
                } else if (seller.equals(user3) && remoteUser3 != null) {
                    if (!cryptoUtils.containsCert(user3)) // TODO
						cryptoUtils.addCertToList(user3, remoteUser3.getCertificate());
                    String nonce = remoteUser3.getNonce(this.id, cryptoUtils.signMessage(this.id));
                    String cnonce = cryptoUtils.generateCNonce();
                    nonceList.put(user3, cnonce);
                    String toSign = nonce + cnonce + this.id + goodId;
                    result = remoteUser3
                            .buyGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
                    goods.put(goodId, result.getGood());
                }
*/
                System.out.println("SUCCESSFUL BUY");
                System.out.println(goodId + " was added to the list of goods!");
                System.out.println("------------------");
                return true;


            }

        } catch (IOException e) {
            rebind();
            return buying(goodId);
        } catch (TransferException e) {
            System.out.println("Buying not possible!");
            return false;
        }
    }

    /*
     * Invoked when a user wants to sell a good
     */

    public synchronized boolean intentionSell(String goodId) {
        Good goodToSell = goods.get(goodId);
        if(goodToSell == null) {
            System.out.println("ERROR: Good not found!");
            return false;
        }

        final int writeTimeStamp = goodToSell.getWriteTimestamp() + 1;

        System.out.println("WriteTimeStamp: " + writeTimeStamp);

        ConcurrentHashMap<String, Result> acksList = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Result> failedAcksList = new ConcurrentHashMap<>();

        CountDownLatch awaitSignal = new CountDownLatch((NUM_NOTARIES + NUM_FAULTS) / 2 + 1);

        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);
            service.execute(() -> {
                try {
                    String nonce = notary.getNonce(this.id);
                    String cnonce = cryptoUtils.generateCNonce();
                    String data = nonce + cnonce + this.id + goodId;

                    Result result = notary
                            .intentionToSell(this.id, goodId, writeTimeStamp, cnonce, cryptoUtils.signMessage(data));

                    if (result != null && cryptoUtils
                            .verifySignature(notaryID, data + result.getContent().hashCode(), result.getSignature())) {
                        System.out.println("Recived WriteTimeStamp: " + result.getWriteTimestamp());
                        if ((Boolean) result.getContent() && result.getWriteTimestamp() == writeTimeStamp) {
                            acksList.put(notaryID, result);
                            awaitSignal.countDown();
                            System.out.println("NotaryID: " + notaryID + "\nResult: " + (Boolean) result.getContent());
                        } else {
                            failedAcksList.put(notaryID, result);
                            awaitSignal.countDown();
                            System.out.println("Result: Invalid good");
                        }
                        System.out.println("-----------------------------");
                        return;
                    } else {
                        System.err.println("ERROR: Signature does not verify");
                        System.out.println("-----------------------------");
                        return;

                    }
                } catch (RemoteException e) {
                    e.printStackTrace();
                    return;
                }
            });

        }

        try {
            awaitSignal.await(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return false;
        }

        if (acksList.size() > (NUM_NOTARIES + NUM_FAULTS) / 2) {
            System.out.println("AcksList: " + acksList.size());
            goods.get(goodId).setForSale();
            goodToSell.setWriteTimestamp(writeTimeStamp);
            return true;
        } else {
            System.out.println("FailedAcksList: " + failedAcksList.size());
            return false;
        }
    }

    /*
     * Invoked to get current state of a good, it returns the current owner and if it is for sale or not
     */
    public synchronized Result stateOfGood(String goodId) {
    	ConcurrentHashMap<Result, Integer> acksList = new ConcurrentHashMap<Result, Integer>();

        CountDownLatch awaitSignal = new CountDownLatch((NUM_NOTARIES + NUM_FAULTS) / 2 + 1);
        for (String notaryID : notaryServers.keySet()) {
            service.execute(() -> {
            	try {
                    Result result;
	            	NotaryInterface notary = notaryServers.get(notaryID);
		            String cnonce = cryptoUtils.generateCNonce();
		            String data = notary.getNonce(this.id) + cnonce + this.id + goodId;
		            		
		            result = notary
		                    .stateOfGood(this.getId(), cnonce, goodId, cryptoUtils.signMessage(data));
		        
			        if (cryptoUtils
			                .verifySignature(notaryID, data + result.getContent().hashCode(), result.getSignature())) {
			        	System.out.println("ok");
			        	Boolean toInsert = true;
			            for(Map.Entry<Result, Integer> entry : acksList.entrySet()){
			               if(entry.getKey().equals(result)) {
			            	   acksList.replace(entry.getKey(), (entry.getValue() + 1));
			            	   toInsert	= false;
			               }
			            }
			            if (toInsert)
			            	acksList.put(result, 1);
			            
			            System.out.println("Owner: " + result.getUserId());
			            System.out.println("For sale: " + (Boolean) result.getContent());
			            System.out.println("-------------------------");
			            
			        } else {
			            System.err.println("ERROR: Signature does not verify");
			            System.out.println("-------------------------");
			            
			        }
                    awaitSignal.countDown();
                    return;
            	} catch (RemoteException e) {
			        rebind();
			        return;
            	}
            });
        }
		    
        
        try {
            awaitSignal.await(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return null;
        }
        
        Map.Entry<Result, Integer> maxEntry = null;
        for(Map.Entry<Result, Integer> entry : acksList.entrySet()){
           if(maxEntry == null || entry.getValue().compareTo(maxEntry.getValue()) > 0)
              maxEntry = entry;
        }
        
        System.out.println("MAP -> " + acksList);

        if (maxEntry.getValue() > (NUM_NOTARIES + NUM_FAULTS) / 2) {
        	System.out.println("QUORUM REACHED!!!!");
        	return maxEntry.getKey();
        }
        else {
        	System.out.println("Quorum not reached...");
        	return null;
        }
    }

    /*
     * Invoked when the server crashes and communications between the user and the notary fail
     */
    private void rebind() {
        notaryServers = Client.locateNotaries();
        
    }


    /*
     * List all current goods
     */
    public void listGoods() {
        for (String goodId : goods.keySet()) {
            Boolean value = goods.get(goodId).forSale();
            System.out.println(goodId + " --> For sale: " + value);
        }
    }

    /*
     * Finds the remaining users on the RMI registry
     */
    private void lookUpUsers() {
        try {
            String[] regList = Naming.list("//localhost:3000");
            for(String s : regList) {
            	if(!s.contains("Notary") && !s.contains(this.id))
            		remoteUsers.put(s.replace("//localhost:3000/", ""), (UserInterface) Naming.lookup(s));
            }
        } catch (MalformedURLException | RemoteException | NotBoundException e) {
            System.err.println("ERROR looking up user");
        }
    }

}