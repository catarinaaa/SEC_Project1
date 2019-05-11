package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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
    private final Boolean verbose = false;

    // List of all goods possessed
    private Map<String, Good> goods;

    // Instance of remote Notary Object
    private TreeMap<String, NotaryInterface> notaryServers;
    private TreeMap<String, UserInterface> remoteUsers = new TreeMap<String, UserInterface>();

    private String keysPath; // KeyStore location
    private String password; // KeyStore password

    private CryptoUtilities cryptoUtils;

    private Map<String, String> nonceList = new HashMap<>();

    private ExecutorService service = Executors.newFixedThreadPool(4);

    private int readID = 0;

    private ConcurrentHashMap<Result, Integer> answers = new ConcurrentHashMap<>();

    private CountDownLatch awaitSignal = new CountDownLatch(1);


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
            for (Map.Entry<String, UserInterface> e : remoteUsers.entrySet()) {
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
            X509Certificate res = notary
                    .connectToNotary(this.id, cnonce, cryptoUtils.getStoredCert(), cryptoUtils.signMessage(toSign));

            cryptoUtils.addCertToList(notaryID, res);
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

        if (verbose) {
            System.out.println("Goods owned:");
            for (String s : map.keySet()) {
                System.out.println("> " + s);
            }
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
    public void connectUser(String id, X509Certificate cert) throws RemoteException {
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
    public synchronized Transfer buyGood(String userId, String goodId, String cnonce, byte[] signature) throws TransferException {
        //ConcurrentHashMap<Transfer, Integer> acksList = new ConcurrentHashMap<Transfer, Integer>();

        Good goodToSell = goods.get(goodId);

        final int writeTimeStamp = goodToSell.getWriteTimestamp() + 1;

        if (verbose)
            System.out.println("WriteTimeStamp: " + writeTimeStamp);

        ConcurrentHashMap<String, Transfer> acksList = new ConcurrentHashMap<>();

        CountDownLatch awaitSignal = new CountDownLatch((NUM_NOTARIES + NUM_FAULTS) / 2 + 1);

        for (String notaryID : notaryServers.keySet()) {
            service.execute(() -> {
                try {
                    Transfer result;
                    NotaryInterface notary = notaryServers.get(notaryID);

                    String toVerify = nonceList.get(userId) + cnonce + userId + goodId;

                    if (!cryptoUtils.verifySignature(userId, toVerify, signature)) {
                        throw new TransferException("Error");
                    }

                    String nonceToNotary = cryptoUtils.generateCNonce();
                    String data = notary.getNonce(this.id) + nonceToNotary + this.id + userId + goodId;

                    result = notary.transferGood(this.getId(), userId, goodId, writeTimeStamp, nonceToNotary,
                            cryptoUtils.signMessage(data));

                    String transferVerify =
                            result.getId() + result.getBuyerId() + result.getSellerId() + result.getGood().getGoodId();

                    if (!verifyCC || cryptoUtils
                            .verifySignature(NOTARY_CC, transferVerify, result.getNotarySignature(),
                                    notaryServers.get(notaryID).getCertificateCC())) {
                        if (result.getGood().getWriteTimestamp() == writeTimeStamp) {
                            acksList.put(notaryID, result);
                            awaitSignal.countDown();
                        }

                        if (verbose)
                            System.out.println("CC Signature verified! Notary confirmed buy good");
                        return;
                    } else {
                        System.err.println("ERROR: CC Signature does not verify");
                        awaitSignal.countDown();
                        throw new TransferException("Error");
                    }
                } catch (IOException e) {
                    rebind();
                    return;
                } catch (TransferException e) {
                    e.printStackTrace();
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

        if (acksList.size() > (NUM_NOTARIES + NUM_FAULTS) / 2) {
            System.out.println("QUORUM REACHED!!!! OMG I'M SELLING A GOOD! LOOK AT ME I AM RICH NOW!!");
            if (verbose)
                System.out.println("Removing good " + goodId + " from my list");
            goods.remove(goodId);
            return (Transfer) acksList.values().toArray()[0];
        } else {
            System.out.println("Quorum not reached...    :(");
            return null;
        }
    }

    /*
     * Invoked when interacting with the users
     */
    public boolean buying(String goodId) {
        try {
            if (goods.containsKey(goodId)) {
                System.out.println("Cannot buy good owned by you!");
                return false;
            }
            Result stateOfGood = stateOfGood(goodId);
            if (stateOfGood == null || false == (Boolean) stateOfGood.getContent()) {
                System.out.println("ERROR: Buying was not possible!");
                System.out.println("------------------");
                return false;
            } else {
                String seller = stateOfGood.getUserId();

                //reconnect to users if one is missing
                if (!remoteUsers.containsKey(seller))
                    connectToUsers();

                Transfer result;
                String nonce = remoteUsers.get(seller).getNonce(this.id, cryptoUtils.signMessage(this.id));
                String cnonce = cryptoUtils.generateCNonce();
                nonceList.put(seller, cnonce);
                String toSign = nonce + cnonce + this.id + goodId;
                result = remoteUsers.get(seller)
                        .buyGood(this.id, goodId, cnonce, cryptoUtils.signMessage(toSign));
                goods.put(goodId, result.getGood());

                System.out.println("SUCCESSFUL BUY! I'M NOW THE OWNER OF A LUXURY GOOD!");
                if (verbose) {
                    System.out.println(goodId + " was added to the list of goods!");
                    System.out.println("------------------");
                }
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
        if (goodToSell == null) {
            System.out.println("ERROR: Good not found!");
            return false;
        }

        final int writeTimeStamp = goodToSell.getWriteTimestamp() + 1;

        if (verbose)
            System.out.println("WriteTimeStamp: " + writeTimeStamp);

        ConcurrentHashMap<String, Result> acksList = new ConcurrentHashMap<>();

        CountDownLatch awaitSignal = new CountDownLatch((NUM_NOTARIES + NUM_FAULTS) / 2 + 1);

        for (String notaryID : notaryServers.keySet()) {
            NotaryInterface notary = notaryServers.get(notaryID);
            service.execute(() -> {
                try {
                    String nonce = notary.getNonce(this.id);
                    String cnonce = cryptoUtils.generateCNonce();
                    String data = nonce + cnonce + this.id + goodId + writeTimeStamp;

                    Result result = notary
                            .intentionToSell(this.id, goodId, writeTimeStamp, cnonce, cryptoUtils.signMessage(data));

                    if (result != null && cryptoUtils
                            .verifySignature(notaryID, data + result.getContent().hashCode(), result.getSignature())) {
                        if (verbose)
                            System.out.println("Received WriteTimeStamp: " + result.getWriteTimestamp());
                        if ((Boolean) result.getContent() && result.getWriteTimestamp() == writeTimeStamp) {
                            acksList.put(notaryID, result);
                            awaitSignal.countDown();
                            if (verbose)
                                System.out.println("NotaryID: " + notaryID + "\nResult: " + (Boolean) result.getContent());
                        } else {
                            awaitSignal.countDown();
                            System.out.println("Result: Invalid good");
                        }
                        if (verbose)
                            System.out.println("-----------------------------");

                    } else {
                        System.err.println("ERROR: Signature does not verify");
                        System.out.println("-----------------------------");

                    }
                } catch (RemoteException e) {
                    e.printStackTrace();
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
            if (verbose)
                System.out.println("AcksList: " + acksList.size());
            System.out.println("Quorum Reached!   :)");
            goods.get(goodId).setForSale();
            goodToSell.setWriteTimestamp(writeTimeStamp);
            return true;
        } else {
            System.out.println("Quorum not reached...    :'(");
            return false;
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
                try {
                    String cnonce = cryptoUtils.generateCNonce();
                    String data = notary.getNonce(this.id) + cnonce + this.id + goodId + readID;

                    Result result = notary
                            .stateOfGood(this.getId(), readID, cnonce, goodId, cryptoUtils.signMessage(data));

                    if (cryptoUtils
                            .verifySignature(notaryID, data + result.getContent().hashCode(), result.getSignature()) && result.getReadID() == readID) {


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

                    } else {
                        System.err.println("ERROR: Signature does not verify");
                        System.out.println("-------------------------");

                    }
                    if (answers.get(result) > (NUM_NOTARIES + NUM_FAULTS) / 2) {
                        System.out.println("Sending signal " + answers.get(result));
                        awaitSignal.countDown();
                    }
                } catch (RemoteException e) {
                    rebind();
                } catch (StateOfGoodException e) {
                    System.out.println(notaryID + ": " + e.getMessage());
                    if(exceptions.incrementAndGet() == 4)
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
            System.out.println("NumberOfTImes: " + answers.get(resultAux));
            if (answers.get(resultAux) > (NUM_NOTARIES + NUM_FAULTS) / 2) {
                result = resultAux;
            }
        }

        System.out.println("OK5");

        if (result == null) {
            System.err.println("ERROR ERROR ERROR ERROR");
        } else {
            System.out.println("QUORUM REACHED!!!!   YOU SHALL HAVE THE STATE!");
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
    public void updateValue(String notaryId, Result result, String nonce, byte[] signature) throws RemoteException {
        String toVerify = nonceList.get(notaryId) + nonce + notaryId + result.hashCode();

        if (cryptoUtils.verifySignature(notaryId, toVerify, signature)) {
            System.out.println("Updating value");
            if (answers.containsKey(result)) {
                answers.replace(result, answers.get(result) + 1);
            } else {
                answers.put(result, 1);
            }

            for (Result resultAux : answers.keySet()) {
                if (answers.get(resultAux) > (NUM_NOTARIES + NUM_FAULTS) / 2) {
                    awaitSignal.countDown();
                    System.out.println("Unblocking thread");
                }
            }
        }
    }

    /*
     * Invoked when the server crashes and communications between the user and the notary fail
     */
    private void rebind() {
        notaryServers = Client.locateNotaries();
        lookUpUsers();

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