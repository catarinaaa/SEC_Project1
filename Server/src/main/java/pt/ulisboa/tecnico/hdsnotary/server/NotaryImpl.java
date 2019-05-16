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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
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
	private ConcurrentHashMap<String, NotaryInterface> remoteNotaries = new ConcurrentHashMap<>();

	// List containing all goods
	private ConcurrentHashMap<String, Good> goodsList = new ConcurrentHashMap<>();

	// List containing nonces for security
	private ConcurrentHashMap<String, String> nonceList = new ConcurrentHashMap<>();

	// List of users
	private ConcurrentHashMap<String, UserInterface> usersList = new ConcurrentHashMap<>();

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

	private ExecutorService service = Executors.newFixedThreadPool(4);

	private ConcurrentHashMap<BroadcastMessage, ArrayList<String>> echoServers = new ConcurrentHashMap<>();
	private ConcurrentHashMap<BroadcastMessage, ArrayList<String>> readyServers = new ConcurrentHashMap<>();
	private ConcurrentHashMap<BroadcastMessage, Boolean> sentEcho = new ConcurrentHashMap<>();
	private ConcurrentHashMap<BroadcastMessage, Boolean> sentReady = new ConcurrentHashMap<>();
	private ConcurrentHashMap<BroadcastMessage, Boolean> delivered = new ConcurrentHashMap<>();

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
		this.TRANSACTIONSPATH = new String[]{"Server/storage/transactions" + id + "Backup.log",
			"Server/storage/transactions" + id + ".log"};
		this.SELLINGLISTPATH = new String[]{"Server/storage/selling" + id + "Backup.log",
			"Server/storage/selling" + id + ".log"};
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

			if (verbose) {
				System.out.println("Creating new SELLING LIST files");
			}
			for (String path : SELLINGLISTPATH) {
				createFiles(path);
			}
			recoverSellingList();

			if (verbose) {
				System.out.println("Creating new TRANSACTIONS files");
			}
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

	private synchronized void locateNotaries() {
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
	public synchronized String getNonce(String userId) throws RemoteException {
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
	public synchronized Result intentionToSell(String userId, String goodId, int writeTimeStamp,
		String cnonce,
		byte[] signature) throws RemoteException, InvalidSignatureException {
		if (userId == null || goodId == null || cnonce == null || signature == null) {
			throw new NullPointerException();
		}

		System.out
			.println("------ INTENTION TO SELL ------\n" + "User: " + userId + "\tGood: " + goodId);

		//verify signature
		String data = nonceList.get(userId) + cnonce + userId + goodId + writeTimeStamp;
		if (!cryptoUtils.verifySignature(userId, data, signature)) {
			throw new InvalidSignatureException(userId);
		}

		Good good;

		// TODO Change!

		// user owns good, good is not already for sale and timestamp is recent
		if ((good = goodsList.get(goodId)) != null && good.getUserId().equals(userId)
			&& !good.forSale() && writeTimeStamp > good.getWriteTimestamp()) {

			// Broadcast message
            if (!broadcastMessage(goodId, true, userId, "", writeTimeStamp))
                return new Result(new Boolean(false), good.getWriteTimestamp(),
                        cryptoUtils.signMessage(data + new Boolean(false).hashCode()));

			good.setForSale();
			System.out.println("TimeStamp: " + writeTimeStamp);
			good.setWriteTimestamp(writeTimeStamp);
			//goodsList.put(goodId, good);
			sellingListUpdate(good.getGoodId());
			sellingListUpdate(String.valueOf(writeTimeStamp));
			System.out.println("Result: TRUE\n-------------------------------\n");

			//send signed result
			Result result = new Result(good.getUserId(), new Boolean(true),
				writeTimeStamp,
				cryptoUtils.signMessage(data + new Boolean(true).hashCode()));

			System.out.println("Listening: " + good.getListening().size());

			Map<String, Integer> listening = good.getListening();
			for (String listener : listening.keySet()) {
				System.out.println("###################################");
				System.out.println("Updating value " + listener);
				UserInterface user = usersList.get(listener);

				if (user == null) {
					lookupUser(listener);
				}

				user = usersList.get(listener);
				System.out.println("OK1");
				String nonce = user.getNonce(this.id, cryptoUtils.signMessage(this.id));
				System.out.println("OK2");
				String cnonceAux = cryptoUtils.generateCNonce();
				System.out.println("OK3");
				Result tmpResult = new Result(good.getUserId(), new Boolean(true),
					good.getWriteTimestamp(),
					listening.get(listener), cryptoUtils.signMessage(""));
				String dataAux = nonce + cnonceAux + this.id + tmpResult.hashCode();
				System.out.println("OK4 - " + dataAux);
				System.out.println(tmpResult);
				user.updateValue(this.id, tmpResult, cnonceAux, cryptoUtils.signMessage(dataAux));
				System.out.println("OK5");

			}

			return result;
		} else {
			System.out.println("Result: FALSE\n-------------------------------\n");
			return new Result(new Boolean(false), good.getWriteTimestamp(),
				cryptoUtils.signMessage(data + new Boolean(false).hashCode()));
		}
	}

	/*
	 * Invoked when a user wants to check if the good is for sale and who the
	 * current owner is
	 */
	@Override
	public synchronized Result stateOfGood(String userId, int readID, String cnonce, String goodId,
		byte[] signature)
		throws RemoteException, StateOfGoodException, InvalidSignatureException {

		if (userId == null || cnonce == null || goodId == null || signature == null) {
			throw new NullPointerException();
		}

		System.out.println("------ STATE OF GOOD ------\nUser: " + userId + "\tGood: " + goodId);

		//verify signature of received message
		String data = nonceList.get(userId) + cnonce + userId + goodId + readID;
		if (!cryptoUtils.verifySignature(userId, data, signature)) {
			throw new InvalidSignatureException(userId);
		}

		Good good;
		if ((good = goodsList.get(goodId)) != null) {
			good.setListener(userId, readID);
			Boolean status = good.forSale();
			System.out.println("Owner: " + good.getUserId() + "\nFor Sale: " + status);
			System.out.println("---------------------------\n");
			// TODO change result
			return new Result(good.getUserId(), status, good.getWriteTimestamp(), readID,
				cryptoUtils.signMessage(data + status.hashCode()));
		}
		System.out.println("ERROR getting state of good");
		System.out.println("Good: " + good);
		System.out.println("Signature verification: " + cryptoUtils
			.verifySignature(userId, data, signature));
		System.out.println("---------------------------\n");
		// TODO change result
		throw new StateOfGoodException(goodId);
	}

	/*
	 * Invoked when a user invokes buyGood in seller, it is an official transfer of goods if the notary verifies that
	 * every parameter is correct
	 */
	@Override
	public synchronized Transfer transferGood(String sellerId, String buyerId, String goodId,
		int writeTimestamp,
		String cnonce, byte[] signature)
		throws IOException, TransferException, InvalidSignatureException {

		if (sellerId == null || buyerId == null || goodId == null || cnonce == null
			|| signature == null) {
			throw new NullPointerException();
		}

		System.out.println("------ TRANSFER GOOD ------");
		System.out.println("Seller: " + sellerId);
		System.out.println("Buyer: " + buyerId);
		System.out.println("Good: " + goodId);

		//verifies signature of received message
		String data = nonceList.get(sellerId) + cnonce + sellerId + buyerId + goodId;
		if (!cryptoUtils.verifySignature(sellerId, data, signature)) {
			throw new InvalidSignatureException(sellerId);
		}

		//verifies the anti-spam mechanism worked
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e1) {
		}
		byte[] messageDigest = md.digest(data.getBytes());
		if (!Pattern.matches("000.*", cryptoUtils.byteArrayToHex(messageDigest))) {
			System.out.println("Result: NO\n---------------------------");
			throw new TransferException("ERROR: anti-spam mechanism failed");
		}
		Good good;

		// Broadcast message
		if (!broadcastMessage(goodId, false, sellerId, "", writeTimestamp)) {
			throw new TransferException("ERROR broadcasting message");
		}

		// verifies if the good exists, if the good is owned by the seller and if it is for sale,
		// write timestamp is recent and anti-spam mechanism matches
		if (!((good = goodsList.get(goodId)) != null && good.getUserId().equals(sellerId)
			&& good.forSale() && writeTimestamp > good.getWriteTimestamp())) {
			System.out.println("Result: NO\n---------------------------");
			printGoods();
			throw new TransferException("ERROR: ");
		}

		System.out.println("OK4");

		//process transfer, updates good and database
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
			System.out.println("Result: TRUE\n---------------------------");
			printGoods();
			return transfer;
		} catch (PKCS11Exception e) {
			System.err.println("ERROR: Signing with CC not possible");
			System.out.println("Result: FALSE\n---------------------------");
			printGoods();
			throw new TransferException("ERROR: Signing with CC not possible!");
		}
	}

	@Override
	public synchronized void confirmRead(String id, String goodId, int readID, String cnonce,
		byte[] signMessage)
		throws RemoteException {
		Good good;
		if ((good = goodsList.get(goodId)) != null) {
			good.removeListener(id, readID);
		}
	}

	//---------------------------------- DB functions ----------------------------------


	private synchronized void recoverSellingList() throws FileNotFoundException {
		if (verbose) {
			System.out.println("Recovering selling list");
		}
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
				if (verbose) {
					System.out.println("Timestamp of good --> " + line);
				}
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
					if (verbose) {
						System.out.println("Timestamp of good --> " + line);
					}
					good.setWriteTimestamp(Integer.parseInt(line));
				}
			} catch (IOException e1) {
				System.out.println("OMG BACKUP IS ALSO CORRUPTED! Could not recover selling list");
			}
		}
	}

	private synchronized void recoverTransactions() throws FileNotFoundException {
		if (verbose) {
			System.out.println("Recovering transactions");
		}
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

				if (verbose) {
					System.out.println(
						"Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: "
							+ splitLine[2] + " Timestamp: " + splitLine[3]);
				}
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
						System.err.println(
							"ERROR: Recovering line in backup file failed. Ignoring line...");
						continue;
					}

					if (verbose) {
						System.out.println(
							"Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: "
								+ splitLine[2]);
					}
					good = goodsList.get(splitLine[2]);
					good.setUserId(splitLine[1]);
					good.setWriteTimestamp(Integer.parseInt(splitLine[3]));
				}
			} catch (IOException e1) {
				System.out
					.println("OMG BACKUP IS ALSO CORRUPTED! Could not recover TRANSACTIONS list");
			}
		}


	}

	private synchronized void saveTransfer(String sellerId, String buyerId, String goodId,
		String writeTimestamp) {
		try {
			for (String path : TRANSACTIONSPATH) {
				outputTransactions = new BufferedWriter(new FileWriter(new File(path), true));
				outputTransactions
					.write(sellerId + ";" + buyerId + ";" + goodId + ";" + writeTimestamp + "\n");
				outputTransactions.flush();
			}
		} catch (IOException e) {
			System.err.println("ERROR: writing to TRANSACTIONS file failed");
		}
	}

	private synchronized void sellingListUpdate(String goodId) {
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

	private synchronized void removeSelling(String goodId) throws IOException {
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

	private synchronized void printGoods() {
		System.out.println("----- LIST OF GOODS -----");
		for (String id : goodsList.keySet()) {
			System.out.println(goodsList.get(id).getUserId() + " - " + id);
		}
		System.out.println("-------------------------\n");
	}

	public synchronized void stop() {
		try {
			inputTransactions.close();
			if (outputTransactions != null) {
				outputTransactions.close();
			}
			if (outputSellings != null) {
				outputSellings.close();
			}
			inputSellings.close();

			if (useCC) {
				pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD);
			}

		} catch (IOException | pteidlib.PteidException e) {
			System.err
				.println("ERROR: Closing files failed. Transactions database may not be updated");
		}

	}

	private synchronized void createFiles(String path) throws IOException {
		File file = new File(path);
		if (!file.exists()) {
			file.createNewFile();
		}
	}

//---------------------------------- CC functions ----------------------------------

	private synchronized byte[] signWithCC(String string) throws PKCS11Exception {
		System.out.println("Signing with Cartao Do Cidadao");
		return pkcs11.C_Sign(p11_session, string.getBytes(Charset.forName("UTF-8")));
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
	private synchronized static byte[] getCertificateInBytes(int n) {
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

	public synchronized static X509Certificate getCertFromByteArray(byte[] certificateEncoded)
		throws CertificateException {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificateEncoded);
		X509Certificate cert = (X509Certificate) f.generateCertificate(in);
		return cert;
	}

	@Override
	public synchronized X509Certificate getCertificateCC() throws RemoteException {
		return certificate;
	}

	@Override
	public synchronized X509Certificate connectToNotary(String userId, String cnounce,
		X509Certificate userCert, byte[] signature)
		throws RemoteException, InvalidSignatureException {
		// TODO verify certificate signature
		cryptoUtils.addCertToList(userId, userCert);

		return cryptoUtils.getStoredCert();

	}

	private synchronized void lookupUser(String userId) {
		UserInterface user = null;
		try {
			user = (UserInterface) Naming.lookup("//localhost:3000/" + userId);
		} catch (NotBoundException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		usersList.put(userId, user);
	}


	@Override
	public synchronized Result getGoodsFromUser(String userId, String cnonce, byte[] signature)
		throws RemoteException, InvalidSignatureException {
		//verify sender
		String toVerify = nonceList.get(userId) + cnonce + userId;
		if (!cryptoUtils.verifySignature(userId, toVerify, signature)) {
			throw new InvalidSignatureException(userId);
		}

		//process
		ConcurrentHashMap<String, Good> map = new ConcurrentHashMap<>();
		for (Good good : goodsList.values()) {
			if (good.getUserId().equals(userId)) {
				map.put(good.getGoodId(), good);
			}
		}
		//return result signed
		String data = toVerify + map.hashCode();
		return new Result(map, cryptoUtils.signMessage(data));
	}

//---------------------------- Double Echo Broadcast functions ----------------------------------

	public synchronized boolean broadcastMessage(String goodId, Boolean forSale, String writerId,
		String newOwner,
		int timeStamp) {
		BroadcastMessage message = new BroadcastMessage(goodId, forSale, writerId, newOwner,
			timeStamp);

		deliveredSignal = new CountDownLatch(1);

		sentReady.put(message, false);
		sentEcho.put(message, false);
		delivered.put(message, false);

		echoSelf(message);

		try {
			System.out.println("WAITING FOR DELIVERIES");
			if (!deliveredSignal.await(15, TimeUnit.SECONDS)) {
				return false;
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
			System.out.println("Timeout");
			return false;
		}
		System.out.println("BROADCAST COMPLETED");
		return true;

	}

	public void echoSelf(BroadcastMessage message) {

		echoServers.compute(message, (key, value) -> {
			if(value == null)
				return new ArrayList<>();
			else {
				value.add(this.id);
				return value;
			}
		});

		for (String notaryID : notariesIDs) {
			if (notaryID.equals(this.id)) {
				continue;
			}

			if (!remoteNotaries.containsKey(notaryID)) {
				locateNotaries();
			}

			NotaryInterface notary = remoteNotaries.get(notaryID);
			System.out.println("SENDING ECHO");
			service.execute(() -> {
				try {
					notary.echoBroadcast(message, this.id);
				} catch (RemoteException e) {
					System.err.println("ERROR broadcasting echo to " + notaryID);
				}
			});
		}
	}

	@Override
	public void echoBroadcast(BroadcastMessage message, String serverID) throws RemoteException {
		System.out.println(this.id + " ECHO BROADCAST FROM " + serverID);

		echoServers.compute(message, (key, value) -> {
			if(value == null)
				return new ArrayList<>();
			else {
				value.add(this.id);
				return value;
			}
		});


		if (echoServers.get(message).size() > (NUM_NOTARIES + NUM_FAULTS) / 2 && !sentEcho.get(message)) {
			triggerSendReady(message);
		}

	}

	@Override
	public void readyBroadcast(BroadcastMessage message, String serverID) throws RemoteException {
		System.out.println(this.id + " READY BROADCAST FROM " + serverID);

		readyServers.compute(message, (key, value) -> {
			if(value == null)
				return new ArrayList<>();
			else {
				value.add(this.id);
				return value;
			}
		});

		if (readyServers.get(message).size() > NUM_FAULTS && !sentReady.get(message)) {
			triggerSendReady(message);

		} else if (readyServers.get(message).size() > 2 * NUM_FAULTS && !delivered.get(message)) {
			delivered.replace(message, false, true);
			deliveredSignal.countDown();
		}


	}

	private void triggerSendReady(BroadcastMessage message) {
		sentReady.replace(message, false, true);

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
			System.out.println("SENDING READY");
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

