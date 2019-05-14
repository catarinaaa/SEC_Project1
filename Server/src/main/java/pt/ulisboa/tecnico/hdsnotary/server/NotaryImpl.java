package pt.ulisboa.tecnico.hdsnotary.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.nio.charset.Charset;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import pt.gov.cartaodecidadao.PteidException;
import pt.ulisboa.tecnico.hdsnotary.library.BroadcastMessage;
import pt.ulisboa.tecnico.hdsnotary.library.CryptoUtilities;
import pt.ulisboa.tecnico.hdsnotary.library.Good;
import pt.ulisboa.tecnico.hdsnotary.library.InvalidSignatureException;
import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;
import pt.ulisboa.tecnico.hdsnotary.library.Result;
import pt.ulisboa.tecnico.hdsnotary.library.StateOfGoodException;
import pt.ulisboa.tecnico.hdsnotary.library.Transfer;
import pt.ulisboa.tecnico.hdsnotary.library.TransferException;
import pt.ulisboa.tecnico.hdsnotary.library.UserInterface;
import pteidlib.PTEID_Certif;
import pteidlib.pteid;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class NotaryImpl extends UnicastRemoteObject implements NotaryInterface, Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private final String keysPath;
    private final String[] TRANSACTIONSPATH;
    private final String[] SELLINGLISTPATH;
    private final String TEMPFILE;
    private final Boolean verbose = false;

    private static final int NUM_NOTARIES = 4;
    private static final int NUM_FAULTS = 1;

    // Singleton
    private static NotaryImpl instance = null;

    private String[] notariesIDs = new String[]{"Notary1", "Notary2", "Notary3", "Notary4"};
    private Map<String, NotaryInterface> remoteNotaries = new HashMap<>();

    // List containing all goods
    private Map<String, Good> goodsList = new HashMap<>();

    // List containing nonces for security
    private Map<String, String> nonceList = new HashMap<>();

    // List of users
    private Map<String, UserInterface> usersList = new HashMap<>();

    private File transactionsFile = null;
    private File sellingListFile = null;
    private BufferedReader inputTransactions = null;
    private BufferedWriter outputTransactions = null;
    private BufferedReader inputSellings = null;
    private BufferedWriter outputSellings = null;
    private int transferId = 1;

    // CC
    private PKCS11 pkcs11;
    private long p11_session;
    private X509Certificate certificate;

    private boolean useCC;

    private CryptoUtilities cryptoUtils;

//	private List<BroadcastMessage> broadcastMessages = Collections
//		.synchronizedList(new ArrayList<>());

    private ExecutorService service = Executors.newFixedThreadPool(4);

//	private ConcurrentHashMap<BroadcastMessage, ArrayList<String>> echoServers = new ConcurrentHashMap<>();
//	private ConcurrentHashMap<BroadcastMessage, ArrayList<String>> readyServers = new ConcurrentHashMap<>();
//
//	private ConcurrentHashMap<BroadcastMessage, Boolean> sentReady = new ConcurrentHashMap<>();
//	private ConcurrentHashMap<BroadcastMessage, Boolean> delivered = new ConcurrentHashMap<>();

    private List<BroadcastMessage> broadcastMessagesReceived = Collections.synchronizedList(new ArrayList<>());

    private CountDownLatch deliveredSignal;

    public static NotaryImpl getInstance(boolean useCC, String id) throws KeyStoreException {
        if (instance == null) {
            try {
                instance = new NotaryImpl(useCC, id);
            } catch (RemoteException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
        return instance;
    }

    private NotaryImpl(boolean cc, String id) throws RemoteException, KeyStoreException {
        super();
        populateList();
        this.useCC = cc;
        this.id = id;

        this.keysPath = "Server/storage/" + id + ".p12";
        this.TRANSACTIONSPATH = new String[]{"Server/storage/transactions" + id + "Backup.txt", "Server/storage/transactions" + id + ".txt"};
        this.SELLINGLISTPATH = new String[]{"Server/storage/selling" + id + "Backup.txt", "Server/storage/selling" + id + ".txt"};
        this.TEMPFILE = "Server/storage/temp" + id + ".txt";

        cryptoUtils = new CryptoUtilities(this.id, keysPath, this.id);

        Scanner scanner = new Scanner(System.in);
        int count = 0;

        if (cc) {

            while (count <= 5) {
                try {
                    setupCititzenCard();
                    break;
                } catch (CertificateException | NoSuchMethodException | SecurityException | ClassNotFoundException
                        | IllegalAccessException | IllegalArgumentException | InvocationTargetException | PteidException
                        | pteidlib.PteidException | PKCS11Exception e1) {
                    System.out.println("Please insert card and press Enter");
                    scanner.nextLine();
                    count++;
                } finally {
                    //exit if reading the citizen card fails 5 times
                    if (count == 5) {
                        System.err.println("ERROR: Number of tries exceeded. Aborting...");
                        scanner.close();
                        System.exit(1);
                    }
                }
            }
        }

        try {

            if (verbose)
                System.out.println("Creating new SELLING LIST files");
            for (String path : SELLINGLISTPATH) {
                createFiles(path);
            }
            recoverSellingList();

            if (verbose)
                System.out.println("Creating new TRANSACTIONS files");
            for (String path : TRANSACTIONSPATH) {
                createFiles(path);
            }

            recoverTransactions();

        } catch (IOException e) {
            System.err.println("ERROR: Creation of databases failed. Aborting...");
            e.printStackTrace();
            System.exit(1);
        }

        locateNotaries();
    }

    private void locateNotaries() {
        try {
            String[] regList = Naming.list("//localhost:3000");
            for (String s : regList) {
                if (s.contains("Notary") && !s.contains(this.id)) {
                    remoteNotaries.put(s.replace("//localhost:3000/", ""),
                            (NotaryInterface) Naming.lookup(s));
                }
            }
        } catch (MalformedURLException | RemoteException | NotBoundException e) {
            System.err.println("ERROR looking up user");
        }
    }

    public String getId() {
        return id;
    }

    /*
     * Generate random number only used once, for prevention of Replay Attacks and
     * Man-In-The-Middle
     */
    @Override
    public String getNonce(String userId) throws RemoteException {
        if (userId == null) {
            throw new NullPointerException();
        }
        if (verbose) {
            System.out.println("Generating nonce for user " + userId);
        }
        String nonce = cryptoUtils.generateCNonce();
        nonceList.put(userId, nonce);
        return nonce;
    }

    /*
     * Invoked when a user wants to sell a particular good
     */
    @Override
    public Result intentionToSell(String userId, String goodId, int writeTimeStamp, String cnonce,
                                  byte[] signature)
            throws RemoteException {
        if (userId == null || goodId == null || cnonce == null || signature == null) {
            throw new NullPointerException();
        }

        System.out
                .println("------ INTENTION TO SELL ------\n" + "User: " + userId + "\tGood: " + goodId);
        Good good;
        String data = nonceList.get(userId) + cnonce + userId + goodId + writeTimeStamp;

        // verifies if good exists, user owns good, good is not already for sale and
        // signature is valid
        if ((good = goodsList.get(goodId)) != null && good.getUserId().equals(userId)
                && !good.forSale() && cryptoUtils.verifySignature(userId, data, signature)
                && writeTimeStamp > good.getWriteTimestamp()) {

            // Broadcast message
            if (!broadcastMessage(goodId, true, userId, "", writeTimeStamp))
                return new Result(new Boolean(false), good.getWriteTimestamp(),
                        cryptoUtils.signMessage(data + new Boolean(false).hashCode()));

            good.setForSale();
            good.setWriteTimestamp(writeTimeStamp);
            goodsList.put(goodId, good);
            sellingListUpdate(good.getGoodId());
            sellingListUpdate(String.valueOf(writeTimeStamp));
            System.out.println("Result: TRUE");
            System.out.println("-------------------------------\n");

            Result result = new Result(new Boolean(true), good.getWriteTimestamp(),
                    cryptoUtils.signMessage(data + new Boolean(true).hashCode()));

            // TODO test, not sure if it is working
            Map<String, Integer> listening = good.getListening();
            for (String listener : listening.keySet()) {
                System.out.println("###################################");
                System.out.println("Updating value " + userId);
                UserInterface user = usersList.get(listener);
                String nonce = user.getNonce(this.id, cryptoUtils.signMessage(this.id));
                String cnonceAux = cryptoUtils.generateCNonce();
                String dataAux = nonce + cnonceAux + this.id + result.hashCode();
                user.updateValue(this.id, result, cnonceAux, cryptoUtils.signMessage(dataAux));
            }

            return result;
        } else {
            System.out.println("Result: FALSE");
            System.out.println("-------------------------------\n");
            return new Result(new Boolean(false), good.getWriteTimestamp(),
                    cryptoUtils.signMessage(data + new Boolean(false).hashCode()));
        }
    }

    /*
     * Invoked when a user wants to check if the good is for sale and who the
     * current owner is
     */
    @Override
    public Result stateOfGood(String userId, int readID, String cnonce, String goodId,
                              byte[] signature)
            throws RemoteException, StateOfGoodException {

        if (userId == null || cnonce == null || goodId == null || signature == null) {
            throw new NullPointerException();
        }

        System.out.println("------ STATE OF GOOD ------\nUser: " + userId + "\tGood: " + goodId);

        String data = nonceList.get(userId) + cnonce + userId + goodId + readID;

        Good good;
        if ((good = goodsList.get(goodId)) != null && cryptoUtils
                .verifySignature(userId, data, signature)) {

            good.setListener(userId, readID);
            Boolean status = good.forSale();
            System.out.println("Owner: " + good.getUserId() + "\nFor Sale: " + status);
            System.out.println("---------------------------\n");
            // TODO change result
            return new Result(good.getUserId(), status, 0, readID,
                    cryptoUtils.signMessage(data + status.hashCode()));
        }
        System.out.println("ERROR getting state of good");
        System.out.println("Good: " + good);
        System.out.println("Signature verification: " + cryptoUtils
                .verifySignature(userId, data, signature));
        System.out.println("---------------------------\n");
        throw new StateOfGoodException(goodId);
    }

    /*
     * Invoked when a user invokes buyGood in seller, it is an official transfer of goods if the notary verifies that
     * every parameter is correct
     */
    @Override
    public Transfer transferGood(String sellerId, String buyerId, String goodId, int writeTimestamp,
                                 String cnonce,
                                 byte[] signature) throws IOException, TransferException {

        if (sellerId == null || buyerId == null || goodId == null || cnonce == null
                || signature == null) {
            throw new NullPointerException();
        }

        System.out.println("------ TRANSFER GOOD ------");

        System.out.println("Seller: " + sellerId);
        System.out.println("Buyer: " + buyerId);
        System.out.println("Good: " + goodId);

        String data = nonceList.get(sellerId) + cnonce + sellerId + buyerId + goodId;
        Good good;

        // verifies if the good exists, if the good is owned by the seller and if it is for sale, and if the signature
        // verifies

        if ((good = goodsList.get(goodId)) != null && good.getUserId().equals(sellerId)
                && good.forSale() && cryptoUtils.verifySignature(sellerId, data, signature)
                && writeTimestamp > good.getWriteTimestamp()) {

            // Broadcast message
            if (!broadcastMessage(goodId, false, sellerId, "", writeTimestamp))
                throw new TransferException("ERROR broadcasting message");


            good.setUserId(buyerId);
            good.notForSale();
            good.setWriteTimestamp(writeTimestamp);
            goodsList.put(goodId, good);
            saveTransfer(sellerId, buyerId, goodId, String.valueOf(writeTimestamp));
            removeSelling(goodId);

            // Sign transfer with Cartao Do Cidadao
            try {
                String toSign = transferId + buyerId + sellerId + goodId;
                System.out.println("Verify: " + toSign);
                Transfer transfer = new Transfer(transferId++, buyerId, sellerId, good,
                        useCC ? signWithCC(toSign) : cryptoUtils.signMessage(toSign));
                System.out.println("Result: TRUE");
                System.out.println("---------------------------");
                printGoods();
                return transfer;
            } catch (PKCS11Exception e) {
                System.err.println("ERROR: Signing with CC not possible");
                System.out.println("Result: FALSE");
                System.out.println("---------------------------");
                printGoods();
                e.printStackTrace();
                throw new TransferException("Signing with CC not possible!");
            }

        }
        System.out.println("Result: NO");
        System.out.println("---------------------------");
        printGoods();
        throw new TransferException("ERROR");

    }

    @Override
    public void confirmRead(String id, String goodId, int readID, String cnonce, byte[] signMessage)
            throws RemoteException {
        Good good;
        if ((good = goodsList.get(goodId)) != null) {
            good.removeListener(id, readID);
        }
    }

    private byte[] signWithCC(String string) throws PKCS11Exception {
        System.out.println("Signing with Cartao Do Cidadao");
        return pkcs11.C_Sign(p11_session, string.getBytes(Charset.forName("UTF-8")));
    }

    private void recoverSellingList() throws FileNotFoundException {
        if (verbose)
            System.out.println("Recovering selling list");
        String line;
        sellingListFile = new File(SELLINGLISTPATH[1]);
        inputSellings = new BufferedReader(new FileReader(sellingListFile));
        try {
            while ((line = inputSellings.readLine()) != null) {
                if (verbose) {
                    System.out.println("GoodId: " + line + " is for sale");
                }
                Good good = goodsList.get(line);
                good.setForSale();
                line = inputSellings.readLine();
                if (verbose)
                    System.out.println("Timestamp of good --> " + line);
                good.setWriteTimestamp(Integer.parseInt(line));
            }
        } catch (IOException e) {
            System.out.println("Using backup file");
            inputSellings = new BufferedReader(new FileReader(new File(SELLINGLISTPATH[0])));
            try {
                while ((line = inputSellings.readLine()) != null) {
                    if (verbose) {
                        System.out.println("GoodId: " + line + " is for sale");
                    }
                    Good good = goodsList.get(line);
                    good.setForSale();
                    line = inputSellings.readLine();
                    if (verbose)
                        System.out.println("Timestamp of good --> " + line);
                    good.setWriteTimestamp(Integer.parseInt(line));
                }
            } catch (IOException e1) {
                System.out.println("OMG BACKUP IS ALSO CORRUPTED! Could not recover selling list");
            }
        }
    }

    private void recoverTransactions() throws FileNotFoundException {
        if (verbose)
            System.out.println("Recovering transactions");
        String line;
        String[] splitLine;
        Good good;
        transactionsFile = new File(TRANSACTIONSPATH[1]);
        inputTransactions = new BufferedReader(new FileReader(transactionsFile));

        try {
            while ((line = inputTransactions.readLine()) != null) {
                splitLine = line.split(";");

                //checks if line is well constructed
                if (splitLine.length != 4 || splitLine[0] == null || splitLine[1] == null
                        || splitLine[2] == null || splitLine[3] == null) {
                    System.err.println("ERROR: Recovering line failed. Ignoring line...");
                    continue;
                }

                if (verbose)
                    System.out.println(
                            "Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: " + splitLine[2] + " Timestamp: " + splitLine[3]);
                good = goodsList.get(splitLine[2]);
                good.setUserId(splitLine[1]);
                good.setWriteTimestamp(Integer.parseInt(splitLine[3]));
            }
        } catch (IOException e) {
            System.out.println("Using backup file");
            inputTransactions = new BufferedReader(new FileReader(new File(TRANSACTIONSPATH[0])));
            try {
                while ((line = inputTransactions.readLine()) != null) {
                    splitLine = line.split(";");

                    //checks if line is well constructed
                    if (splitLine.length != 4 || splitLine[0] == null || splitLine[1] == null
                            || splitLine[2] == null || splitLine[3] == null) {
                        System.err.println("ERROR: Recovering line in backup file failed. Ignoring line...");
                        continue;
                    }

                    if (verbose)
                        System.out.println(
                                "Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: " + splitLine[2]);
                    good = goodsList.get(splitLine[2]);
                    good.setUserId(splitLine[1]);
                    good.setWriteTimestamp(Integer.parseInt(splitLine[3]));
                }
            } catch (IOException e1) {
                System.out.println("OMG BACKUP IS ALSO CORRUPTED! Could not recover TRANSACTIONS list");
            }
        }


    }

    private void saveTransfer(String sellerId, String buyerId, String goodId, String writeTimestamp) {
        try {
            for (String path : TRANSACTIONSPATH) {
                outputTransactions = new BufferedWriter(new FileWriter(new File(path), true));
                outputTransactions.write(sellerId + ";" + buyerId + ";" + goodId + ";" + writeTimestamp + "\n");
                outputTransactions.flush();
            }
        } catch (IOException e) {
            System.err.println("ERROR: writing to TRANSACTIONS file failed");
        }
    }

    private void sellingListUpdate(String goodId) {
        try {
            for (String path : SELLINGLISTPATH) {
                outputSellings = new BufferedWriter(new FileWriter(new File(path), true));
                outputSellings.write(goodId + "\n");
                outputSellings.flush();
            }
        } catch (IOException e) {
            System.err.println("ERROR: writing to SELLINGS file");
        }
    }


    private void populateList() {
        goodsList.put("good1", new Good("Alice", "good1"));
        goodsList.put("good2", new Good("Alice", "good2"));
        goodsList.put("good3", new Good("Bob", "good3"));
        goodsList.put("good4", new Good("Bob", "good4"));
        goodsList.put("good5", new Good("Charlie", "good5"));
        goodsList.put("good6", new Good("Charlie", "good6"));
    }

    private void removeSelling(String goodId) throws IOException {
        //Remove given goodId from selling list
        for (String path : SELLINGLISTPATH) {
            File tempFile = new File(TEMPFILE);
            String currentLine;
            BufferedWriter tempWriter = new BufferedWriter(new FileWriter(tempFile));
            inputSellings = new BufferedReader(new FileReader(new File(path)));
            while ((currentLine = inputSellings.readLine()) != null) {
                // trim newline when comparing with lineToRemove
                String trimmedLine = currentLine.trim();
                if (trimmedLine.equals(goodId)) {
                    inputSellings.readLine(); //skips next line (timestamp)
                    continue;
                }
                tempWriter.write(currentLine + ("\n"));
            }
            tempWriter.close();
            tempFile.renameTo(new File(path));
        }
    }

    private void printGoods() {
        System.out.println("----- LIST OF GOODS -----");
        for (String id : goodsList.keySet()) {
            System.out.println(goodsList.get(id).getUserId() + " - " + id);
        }
        System.out.println("-------------------------\n");
    }

    public void stop() {
        try {
            inputTransactions.close();
            if (outputTransactions != null)
                outputTransactions.close();
            if (outputSellings != null)
                outputSellings.close();
            inputSellings.close();

            if (useCC) {
                pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD);
            }

        } catch (IOException | pteidlib.PteidException e) {
            System.err
                    .println("ERROR: Closing files failed. Transactions database may not be updated");
        }

    }

    private void createFiles(String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            file.createNewFile();
        }
    }


    private void setupCititzenCard()
            throws PteidException, CertificateException, pteidlib.PteidException,
            PKCS11Exception, NoSuchMethodException, SecurityException, ClassNotFoundException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException {
        System.loadLibrary("pteidlibj");
        pteid.Init(""); // Initializes the eID Lib
        pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)

        String osName = System.getProperty("os.name");
        String javaVersion = System.getProperty("java.version");

        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();

        String libName = "libpteidpkcs11.so";

        certificate = getCertFromByteArray(getCertificateInBytes(0));

        Class pkcs11Class;

        pkcs11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");

        if (javaVersion.startsWith("1.5.")) {
            Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance",
                    new Class[]{String.class, CK_C_INITIALIZE_ARGS.class, boolean.class});
            pkcs11 = (PKCS11) getInstanceMethode.invoke(null, new Object[]{libName, null, false});
        } else {
            Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance",
                    new Class[]{String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class});
            pkcs11 = (PKCS11) getInstanceMethode.invoke(null,
                    new Object[]{libName, "C_GetFunctionList", null, false});
        }

        // Open the PKCS11 session
        p11_session = pkcs11.C_OpenSession(0, PKCS11Constants.CKF_SERIAL_SESSION, null, null);

        // Token login
        pkcs11.C_Login(p11_session, 1, null);
        CK_SESSION_INFO info = pkcs11.C_GetSessionInfo(p11_session);

        // Get available keys
        CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[1];
        attributes[0] = new CK_ATTRIBUTE();
        attributes[0].type = PKCS11Constants.CKA_CLASS;
        attributes[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);

        pkcs11.C_FindObjectsInit(p11_session, attributes);
        long[] keyHandles = pkcs11.C_FindObjects(p11_session, 5);

        long signatureKey = keyHandles[0]; // test with other keys to see what you get
        pkcs11.C_FindObjectsFinal(p11_session);

        // initialize the signature method
        CK_MECHANISM mechanism = new CK_MECHANISM();
        mechanism.mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
        mechanism.pParameter = null;
        pkcs11.C_SignInit(p11_session, mechanism, signatureKey);

    }

    // Returns the CITIZEN AUTHENTICATION CERTIFICATE
    public static byte[] getCitizenAuthCertInBytes() {
        return getCertificateInBytes(0);
    }

    // Returns the n-th certificate, starting from 0
    private static byte[] getCertificateInBytes(int n) {
        byte[] certificate_bytes = null;
        try {
            PTEID_Certif[] certs = pteid.GetCertificates();
            int i = 0;

            certificate_bytes = certs[n].certif;

        } catch (pteidlib.PteidException e) {
            e.printStackTrace();
        }
        return certificate_bytes;
    }

    public static X509Certificate getCertFromByteArray(byte[] certificateEncoded)
            throws CertificateException {
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificateEncoded);
        X509Certificate cert = (X509Certificate) f.generateCertificate(in);
        return cert;
    }

    @Override
    public X509Certificate getCertificateCC() throws RemoteException {
        return certificate;
    }

    @Override
    public X509Certificate connectToNotary(String userId, String cnounce,
                                           X509Certificate userCert, byte[] signature)
            throws RemoteException, InvalidSignatureException {
        // TODO verify certificate signature
        cryptoUtils.addCertToList(userId, userCert);

//		UserInterface user = null;
//		try {
//			user = (UserInterface) Naming.lookup("//localhost:3000/" + userId);
//		} catch (NotBoundException e) {
//			e.printStackTrace();
//		} catch (MalformedURLException e) {
//			e.printStackTrace();
//		}
//		usersList.put(userId, user);

        return cryptoUtils.getStoredCert();

    }

    @Override
    public Result getGoodsFromUser(String userId, String cnonce, byte[] signature)
            throws RemoteException, InvalidSignatureException {
        //verify sender
        String toVerify = nonceList.get(userId) + cnonce + userId;
        if (!cryptoUtils.verifySignature(userId, toVerify, signature)) {
            throw new InvalidSignatureException();
        }

        //process
        TreeMap<String, Good> map = new TreeMap<>();
        for (Good good : goodsList.values()) {
            if (good.getUserId().equals(userId)) {
                map.put(good.getGoodId(), good);
            }
        }
        //return result signed
        String data = toVerify + map.hashCode();
        return new Result(map, cryptoUtils.signMessage(data));
    }


    public boolean broadcastMessage(String goodId, Boolean forSale, String writerId, String newOwner,
                                    int timeStamp) {
        BroadcastMessage message = new BroadcastMessage(goodId, forSale, writerId, newOwner, timeStamp);

//		if(!echoServers.containsKey(message)) echoServers.put(message, new ArrayList<>());
//		if(!readyServers.containsKey(message)) readyServers.put(message, new ArrayList<>());
//		if(!sentReady.containsKey(message)) sentReady.put(message, false);
//		if(!delivered.containsKey(message)) delivered.put(message, false);

        deliveredSignal = new CountDownLatch(1);

        echoSelf(message);

        try {
            System.out.println("WAITING FOR DELIVERIES");
            if (!deliveredSignal.await(15, TimeUnit.SECONDS))
                return false;
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.out.println("Timeout");
            return false;
        }
        return true;

    }

    public void echoSelf(BroadcastMessage message) {
        // check if message exists in list broadcastMessages
        // easy way xD
        BroadcastMessage msg;
        if (!broadcastMessagesReceived.contains(message)) {
            broadcastMessagesReceived.add(message);
            msg = message;

        } else {
            msg = broadcastMessagesReceived.get(broadcastMessagesReceived.indexOf(message));

        }

        msg.addEchoServer(this.id);

        for (String notaryID : notariesIDs) {
            if (notaryID.equals(this.id)) {
                continue;
            }

            // manhoso
            if (!remoteNotaries.containsKey(notaryID)) {
                locateNotaries();
            }

            NotaryInterface notary = remoteNotaries.get(notaryID);

            service.execute(() -> {
                try {
                    notary.echoBroadcast(msg, this.id);
                } catch (RemoteException e) {
                    System.err.println("ERROR broadcasting echo to " + notaryID);
                }
            });
        }
    }

    @Override
    public void echoBroadcast(BroadcastMessage message, String serverID) throws RemoteException {
        System.out.println(this.id + " ECHO BROADCAST FROM " + serverID);

        BroadcastMessage msg;

        if (!broadcastMessagesReceived.stream().anyMatch(o -> o.equals(message))) {
            broadcastMessagesReceived.add(message);
            msg = message;
            System.out.println("TEST 1");
        } else {
            System.out.println("TEST 2");
            msg = broadcastMessagesReceived.get(broadcastMessagesReceived.indexOf(message));

            for (String id : message.getEchoServers()) {
                if (!msg.getEchoServers().contains(id)) {
                    System.out.println("Adding to message");
                    msg.addEchoServer(id);
                }
            }

        }

        System.out.println("echoServers size: " + (msg.echoServersSize() + " " + (msg.echoServersSize() > (NUM_NOTARIES + NUM_FAULTS) / 2)));
        System.out.println("sentReady: " + msg.checkReadyServer(this.id));
        System.out.println(msg);


        for (String i : msg.getEchoServers()) {
            System.out.println("ServerInMessage: " + i);
        }

        if (msg.echoServersSize() > (NUM_NOTARIES + NUM_FAULTS) / 2 && !msg.checkReadyServer(this.id)) {
            triggerSendReady(msg);
            System.out.println("READY COMPLETED");
        }

    }

    @Override
    public void readyBroadcast(BroadcastMessage message, String serverID) throws RemoteException {
        System.out.println(this.id + " READY BROADCAST FROM " + serverID);

        BroadcastMessage msg;


        if (!broadcastMessagesReceived.contains(message)) {
            broadcastMessagesReceived.add(message);
            msg = message;
        } else {
            msg = broadcastMessagesReceived.get(broadcastMessagesReceived.indexOf(message));

            for (String id : message.getEchoServers()) {
                if (!msg.getReadyServers().contains(id)) {
                    msg.addReadyServer(id);
                }
            }

        }

        if (msg.readyServersSize() > NUM_FAULTS && !msg.checkReadyServer(this.id)) {
            triggerSendReady(msg);

        } else if (msg.readyServersSize() > 2 * NUM_FAULTS && !msg.checkDeliveredServer(this.id)) {
            msg.addDeliveredServer(this.id);
            deliveredSignal.countDown();
        }


    }

    private void triggerSendReady(BroadcastMessage message) {
        message.addReadyServer(this.id);

        for (String notaryID : notariesIDs) {
            NotaryInterface notary;
            if (notaryID.equals(this.id)) {
                notary = this;
            } else {
                // manhoso
                if (!remoteNotaries.containsKey(notaryID)) {
                    locateNotaries();
                }
                notary = remoteNotaries.get(notaryID);
            }

            service.execute(() -> {
                try {
                    notary.readyBroadcast(message, this.id);
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
            });

        }
    }
}

