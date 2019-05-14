package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import pt.ulisboa.tecnico.hdsnotary.library.CryptoUtilities;
import pt.ulisboa.tecnico.hdsnotary.library.Good;
import pt.ulisboa.tecnico.hdsnotary.library.InvalidSignatureException;
import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;
import pt.ulisboa.tecnico.hdsnotary.library.Result;
import pt.ulisboa.tecnico.hdsnotary.library.StateOfGoodException;
import pt.ulisboa.tecnico.hdsnotary.library.Transfer;
import pt.ulisboa.tecnico.hdsnotary.library.TransferException;
import pt.ulisboa.tecnico.hdsnotary.library.UserInterface;

public class User extends UnicastRemoteObject implements UserInterface {

    private static final long serialVersionUID = 1L;

    private static final long TIMEOUT = 15;
    private static final int NUM_NOTARIES = 4;
    private static final int NUM_FAULTS = 1;

    private static final String[] NOTARY_LIST = new String[]{"Notary1", "Notary2", "Notary3", "Notary4"};
    private static final String NOTARY_CC = "CertCC";

    private final String id;
    private final Boolean verifyCC;
    private final Boolean verbose = true;

    // List of all goods possessed
    private ConcurrentHashMap<String, Good> goods;

    // Instance of remote Notary Object
    private ConcurrentHashMap<String, NotaryInterface> notaryServers;
    private ConcurrentHashMap<String, UserInterface> remoteUsers = new ConcurrentHashMap<String, UserInterface>();

    private String keysPath; // KeyStore location
    private String password; // KeyStore password

    private CryptoUtilities cryptoUtils;

    private ConcurrentHashMap<String, String> nonceList = new ConcurrentHashMap<>();

    private ExecutorService service = Executors.newFixedThreadPool(4);

    private int readID = 0;

    private ConcurrentHashMap<Result, Integer> answers = new ConcurrentHashMap<Result, Integer>();

    private CountDownLatch awaitSignal = new CountDownLatch(1);


    public User(String id, ConcurrentHashMap<String, NotaryInterface> notaryServers, Boolean verifyCC)
            throws RemoteException, KeyStoreException, InvalidSignatureException {

        this.id = id;
        this.notaryServers = notaryServers;
        this.verifyCC = verifyCC;

        this.keysPath = "Client/storage/" + id + ".p12";
        this.password = id + "1234";

        cryptoUtils = new CryptoUtilities(this.id, this.keysPath, this.password);

        System.out.println("Initializing user " + id);

        System.out.println("1");
        connectToNotary();
        System.out.println("2");
        getGoodFromUser();
        System.out.println("3");

        connectToUsers();

    }

    /*
     * Function to look and change certificates with users binded in the RMI registry
     */
    private void connectToUsers() {

        lookUpUsers();
        try {
            for (Map.Entry<String, UserInterface> e : remoteUsers.entrySet()) {
                cryptoUtils.addCertToList(e.getKey(), e.getValue().getCertificate());
                e.getValue().connectUser(this.id, getCertificate());
            }
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    /*
     * Function to change certificates with notary
     */
    private void connectToNotary() throws RemoteException, InvalidSignatureException {
        // TODO verify signatures
        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);

            String cnonce = cryptoUtils.generateCNonce();
            String toSign = notary.getNonce(this.id) + cnonce + this.id;
            X509Certificate res = notary
                    .connectToNotary(this.id, cnonce, cryptoUtils.getStoredCert(), cryptoUtils.signMessage(toSign));

            cryptoUtils.addCertToList(notaryID, res);
        }
    }

    /*
     * Function to obtain goods owned by the user
     */
    public void getGoodFromUser() throws RemoteException {
        ConcurrentHashMap<String, Good> map = null;

        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);
            
            //send signed message
            String cnonce = cryptoUtils.generateCNonce();
            String toSign = notary.getNonce(this.id) + cnonce + this.id;
            Result res = null;
            System.out.println("g1");

            try {
                res = notary.getGoodsFromUser(this.id, cnonce, cryptoUtils.signMessage(toSign));
            } catch (InvalidSignatureException e) {
                System.err.println(e.getMessage());
            }
            System.out.println("g2");

            //verify received message
            String toVerify = toSign + res.getContent().hashCode();
            if (!cryptoUtils.verifySignature(notaryID, toVerify, res.getSignature())) {
                System.err.println("ERROR: Signature could not be verified");
            }
            System.out.println("g3");

            map = (ConcurrentHashMap<String, Good>) res.getContent();
        }

        if (verbose) {
            System.out.println("Goods owned:");
            for (String s : map.keySet()) {
                System.out.println("> " + s);
            }
        }
        goods = map;
    }

    public String getId() {
        return id;
    }

    public Map<String, Good> getGoods() {
        return goods;
    }

    @Override
    public void connectUser(String id, X509Certificate cert) throws RemoteException {
        cryptoUtils.addCertToList(id, cert);
    }

    @Override
    public X509Certificate getCertificate() throws RemoteException {
        return cryptoUtils.getStoredCert();
    }


    /*
     * Function to obtain a nounce for communication
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
    public synchronized Transfer transferGood(String userId, String goodId, String cnonce, byte[] signature) throws TransferException {

        Good goodToSell = goods.get(goodId);

        //writer increment timestamp
        final int writeTimeStamp = goodToSell.getWriteTimestamp() + 1;
        if (verbose)
            System.out.println("--> WriteTimeStamp sent: " + writeTimeStamp);

        ConcurrentHashMap<String, Transfer> acksList = new ConcurrentHashMap<>();
        CountDownLatch awaitSignal = new CountDownLatch((NUM_NOTARIES + NUM_FAULTS) / 2 + 1);

        for (String notaryID : notaryServers.keySet()) {
            service.execute(() -> {
                try {
                    Transfer result;
                    NotaryInterface notary = notaryServers.get(notaryID);

                    //verify message received from other user
                    String toVerify = nonceList.get(userId) + cnonce + userId + goodId;
                    if (!cryptoUtils.verifySignature(userId, toVerify, signature))
                        throw new InvalidSignatureException(userId);
                   

                    //anti-spam mechanism
                    String nonceToNotary = cryptoUtils.generateCNonce();
                    MessageDigest md = MessageDigest.getInstance("SHA-256"); 
                    String hashed = "";
                    String data = "";
                    while(!Pattern.matches("1234.*", hashed)) {
                    	nonceToNotary = ((new BigInteger(nonceToNotary)).add(BigInteger.ONE)).toString();
                    	data = notary.getNonce(this.id) + nonceToNotary + this.id + userId + goodId;
                        byte[] messageDigest = md.digest(data.getBytes()); 
                        hashed = cryptoUtils.byteArrayToHex(messageDigest);
                    }
                    System.out.println("--> hash generated: " + nonceToNotary);
                    
                    //send signed message to notary           
                    result = notary.transferGood(this.getId(), userId, goodId, writeTimeStamp, nonceToNotary,
                            cryptoUtils.signMessage(data));
                    
                    //verify signature with CC
                    String transferVerify =
                            result.getId() + result.getBuyerId() + result.getSellerId() + result.getGood().getGoodId();
                    if(verifyCC)
                    	if(!cryptoUtils.verifySignature(NOTARY_CC, transferVerify, result.getNotarySignature(),
                                    notaryServers.get(notaryID).getCertificateCC()))
                    		throw new InvalidSignatureException(NOTARY_CC);
                    	
                    if (result.getGood().getWriteTimestamp() == writeTimeStamp) {
                        acksList.put(notaryID, result);
                        awaitSignal.countDown();
                    } else 
                    	throw new TransferException("ERROR: Timestamp does not match");
                    
                    if (verbose)
                        System.out.println("--> CC Signature verified! Notary confirmed buy good");
                    return;
                } catch (IOException e) {
                    rebind();
                    return;
                } catch (InvalidSignatureException | TransferException e) {
                	System.err.println(e.getMessage());
                    acksList.put(notaryID, null);
                	awaitSignal.countDown();
                } catch (NoSuchAlgorithmException e) {
                    acksList.put(notaryID, null);
                	awaitSignal.countDown();
				}
            });
        }

        try {
            awaitSignal.await(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
            throw new TransferException("ERROR: quorum waiting failed");
        }

        //checks if enough notaries respond
        if (acksList.size() > (NUM_NOTARIES + NUM_FAULTS) / 2) {
            System.out.println("--> Quorum reached");
            if (verbose)
                System.out.println("--> Removing good " + goodId + " from my list");
            
            //find highest timestamp to return
            //ensures the response is fresh
            Transfer maxGood = null;
            for(Map.Entry<String, Transfer> e : acksList.entrySet()) {
            	if(e.getValue() != null)
            		if(maxGood == null)
            			maxGood = e.getValue();
            		else if(maxGood.getGood().getWriteTimestamp() < e.getValue().getGood().getWriteTimestamp())
            			maxGood = e.getValue();
            }         
            if(maxGood != null) {
            	goods.remove(goodId);
            	return maxGood;
            }
            else throw new TransferException("ERROR: transfer not possible");
        } else {
            System.out.println("--> Quorum not reached...    :(");
            throw new TransferException("ERROR: quorum not reached");
        }
    }

    
    
    /*
     * Invoked when a user wants to buy a good
     */
    public void buying(String goodId) {
        try {
            if (goods.containsKey(goodId)) {
                throw new TransferException("ERROR: good already owned");
            }
            
            Result stateOfGood = stateOfGood(goodId);
            if (stateOfGood == null || false == (Boolean) stateOfGood.getContent()) {
                throw new TransferException("ERROR: stateOfGoof failed");
            }
            String seller = stateOfGood.getUserId();

            //reconnect to users if one is missing
            if (!remoteUsers.containsKey(seller))
                connectToUsers();

            //send signed message
            Transfer result;
            String nonce = remoteUsers.get(seller).getNonce(this.id, cryptoUtils.signMessage(this.id));
            String cnonce = cryptoUtils.generateCNonce();
            nonceList.put(seller, cnonce);
            String toSign = nonce + cnonce + this.id + goodId;
            result = remoteUsers.get(seller).transferGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
            
            //TODO verify sign
            
            goods.put(goodId, result.getGood());
            if (verbose) {
                System.out.println("-->" + goodId + " was added to the list of goods!");
                System.out.println("Result: TRUE\n------------------");
            }
        } catch (IOException e) {
            rebind();
            buying(goodId);
        } catch (TransferException e) {
        	System.err.println(e.getMessage());
            System.out.println("Result: FALSE\n------------------");
        }
    }

    /*
     * Invoked when a user wants to sell a good
     */

    public synchronized void intentionSell(String goodId) {
        Good goodToSell = goods.get(goodId);
        if (goodToSell == null) {
            System.err.println("ERROR: Good not found!");
            System.out.println("Result: FALSE\n------------------");
            return;
        }

        //writer increments timestamp
        final int writeTimeStamp = goodToSell.getWriteTimestamp() + 1;

        if (verbose)
            System.out.println("WriteTimeStamp: " + writeTimeStamp);

        ConcurrentHashMap<String, Result> acksList = new ConcurrentHashMap<>();

        CountDownLatch awaitSignal = new CountDownLatch((NUM_NOTARIES + NUM_FAULTS) / 2 + 1);

        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);
            service.execute(() -> {
                try {                    
                	//send signed message
                    String nonce = notary.getNonce(this.id);
                    String cnonce = cryptoUtils.generateCNonce();
                    String data = nonce + cnonce + this.id + goodId + writeTimeStamp;
                    Result result = notary.intentionToSell(this.id, goodId, writeTimeStamp, cnonce, cryptoUtils.signMessage(data));

                    //verify signature of receive message
                    if (!cryptoUtils.verifySignature(notaryID, data + result.getContent().hashCode(), result.getSignature()))
                    	throw new InvalidSignatureException(notaryID);
                    if (verbose)
                        System.out.println("Received WriteTimeStamp: " + result.getWriteTimestamp());
                    
                    //check if timestamp matches
                    if ((Boolean) result.getContent() && result.getWriteTimestamp() == writeTimeStamp) {
                        acksList.put(notaryID, result);
                        awaitSignal.countDown();
                        if (verbose)
                            System.out.println("NotaryID: " + notaryID + "\nResult: " + (Boolean) result.getContent());

                    } else {
                        acksList.put(notaryID, null);
                        awaitSignal.countDown();
                        System.out.println("Result: Invalid good");
                    }

                } catch (RemoteException e) {
                    rebind();
                } catch(InvalidSignatureException e) {
                	acksList.put(notaryID, null);
                    awaitSignal.countDown();
                }
            });

        }

        //waits for notaries replies
        try {
            awaitSignal.await(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            System.out.println("Result: FALSE\n------------------");
            return;
        }

        // checks if quorum was reached
        if (acksList.size() > (NUM_NOTARIES + NUM_FAULTS) / 2) {
            if (verbose)
                System.out.println("--> AcksList: " + acksList.size());
            System.out.println("--> Quorum Reached");
            
            Result result = findMaxResult(new ArrayList<Result>(acksList.values()));       

            if(result != null) {
	            goods.get(goodId).setForSale();
	            goodToSell.setWriteTimestamp(writeTimeStamp);
	            System.out.println("Result: TRUE\n------------------");
            } else
                System.out.println("Result: FALSE\n------------------");
            	

        } else {
            System.out.println("--> Quorum not reached...");
            System.out.println("Result: FALSE\n------------------");

        }
    }

    /*
     * Invoked to get current state of a good, it returns the current owner and if it is for sale or not
     */
    public synchronized Result stateOfGood(String goodId) {

        answers.clear();

        awaitSignal = new CountDownLatch(1);

        readID++;

        AtomicInteger exceptions = new AtomicInteger(0);

        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);

            service.execute(() -> {
            	Result result = null;
                try {
                	//send signed message
                    String cnonce = cryptoUtils.generateCNonce();
                    String data = notary.getNonce(this.id) + cnonce + this.id + goodId + readID;

                    result = notary
                            .stateOfGood(this.getId(), readID, cnonce, goodId, cryptoUtils.signMessage(data));

                    //verify received message
                    if (!cryptoUtils
                            .verifySignature(notaryID, data + result.getContent().hashCode(), result.getSignature()) && result.getReadID() == readID)
                    	throw new InvalidSignatureException(notaryID);


                    int count = answers.containsKey(result) ? answers.get(result) + 1 : 1;
                    answers.put(result, count);

                    System.out.println("Size thread: " + answers.keySet().size());
//                        System.out.println("Contains: " + answers.containsKey(result));
//                        System.out.println("Times: " + answers.get(result));


                    if (verbose) {
                        System.out.println("Owner: " + result.getUserId());
                        System.out.println("For sale: " + result.getContent());
                        System.out.println("-------------------------");
                    }

                } catch (RemoteException e) {
                    rebind();
                } catch (StateOfGoodException | InvalidSignatureException e) {
                    System.out.println(notaryID + ": " + e.getMessage());
                    if(exceptions.incrementAndGet() == 4)
                        awaitSignal.countDown();
                }
                
                if (answers.get(result) > (NUM_NOTARIES + NUM_FAULTS) / 2) {
                    System.out.println("Sending signal " + answers.get(result));
                    awaitSignal.countDown();
                }
            });
        }

        try {
            if (awaitSignal.await(TIMEOUT, TimeUnit.SECONDS) == false)
                return null;
        } catch (InterruptedException e) {
            e.printStackTrace();
            return null;
        }

        Result result = null;
        System.out.println("Size: " + answers.keySet().size());
        for (Result resultAux : answers.keySet()) {
            if (answers.get(resultAux) > (NUM_NOTARIES + NUM_FAULTS) / 2) {
                result = resultAux;
            }
        }

        if (result == null) {
            System.err.println("ERROR ERROR ERROR ERROR");
        } else {
            System.out.println("Quorum Reached");
            System.out.println("Result: " + result);
            System.out.println("Owner: " + result.getUserId() + " For Sale: " + result.getContent());
        }

        for (String notaryID : notaryServers.keySet()) {

            try {
                NotaryInterface notary = notaryServers.get(notaryID);
                String cnonce = cryptoUtils.generateCNonce();
                String data = notary.getNonce(this.id) + cnonce + this.id + readID;

                notary.confirmRead(this.id, goodId, this.readID, cnonce, cryptoUtils.signMessage(data));
            } catch (RemoteException e) {
                e.printStackTrace();
                System.err.println("ERROR: Could not confirm read");
            }

        }

        return result;
    }

    @Override
    // TODO test
    public void updateValue(String notaryId, Result result, String nonce, byte[] signature) throws RemoteException {

        System.out.println("Hello world!\nThis is a test");
        //        String toVerify = nonceList.get(notaryId) + nonce + notaryId + result.hashCode();
//
//        if (cryptoUtils.verifySignature(notaryId, toVerify, signature)) {
//            System.out.println("Updating value");
//            if (answers.containsKey(result)) {
//                answers.replace(result, answers.get(result) + 1);
//            } else {
//                answers.put(result, 1);
//            }
//
//            for (Result resultAux : answers.keySet()) {
//                if (answers.get(resultAux) > (NUM_NOTARIES + NUM_FAULTS) / 2) {
//                    awaitSignal.countDown();
//                    System.out.println("Unblocking thread");
//                }
//            }
//        }
    }

    /*
     * Invoked when the server crashes and communications between the user and the notary fail
     */
    private void rebind() {
        notaryServers = Client.locateNotaries();
        connectToUsers();
        //lookUpUsers();

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
            for (String s : regList) {
                if (!s.contains("Notary") && !s.contains(this.id))
                    remoteUsers.put(s.replace("//localhost:3000/", ""), (UserInterface) Naming.lookup(s));
            }
        } catch (MalformedURLException | RemoteException | NotBoundException e) {
            System.err.println("ERROR looking up user");
        }
    }

    /*
     * Return the ack result with the highest timestamp
     */
    
    private Result findMaxResult(List<Result> resultsList) {
        int max = 0;
        for (int i = 0; i < resultsList.size(); i++) {
            if (resultsList.get(i).getWriteTimestamp() > resultsList.get(max).getWriteTimestamp()) {
                max = i;
            }
        }
        return resultsList.get(max);
    }


}