package pt.ulisboa.tecnico.hdsnotary.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import java.util.TreeMap;
import pt.gov.cartaodecidadao.PteidException;
import pt.ulisboa.tecnico.hdsnotary.library.CryptoUtilities;
import pt.ulisboa.tecnico.hdsnotary.library.Good;
import pt.ulisboa.tecnico.hdsnotary.library.InvalidSignatureException;
import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;
import pt.ulisboa.tecnico.hdsnotary.library.Result;
import pt.ulisboa.tecnico.hdsnotary.library.Transfer;
import pt.ulisboa.tecnico.hdsnotary.library.TransferException;
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
	private final String TRANSACTIONSPATH;
	private final String SELLINGLISTPATH;
	private final String TEMPFILE;
	private HashMap<String, X509Certificate> certList = new HashMap<String, X509Certificate>();

	// Singleton
	private static NotaryImpl instance = null;

	// List containing all goods
	private TreeMap<String, Good> goodsList = new TreeMap<>();

	// List containing goods that are for sale
	private ArrayList<String> goodsToSell = new ArrayList<>();

	// List containing nonces for security
	private TreeMap<String, String> nonceList = new TreeMap<>();

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
		this.TRANSACTIONSPATH = "Server/storage/transactions" + id + ".txt";
		this.SELLINGLISTPATH = "Server/storage/selling" + id + ".txt";
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

			createDatabases();

			// Recovering list of goods to sell
			inputSellings = new BufferedReader(new FileReader(sellingListFile));
			outputSellings = new BufferedWriter(new FileWriter(sellingListFile, true));
			recoverSellingList();

			// Recovering transactions from transactions file
			inputTransactions = new BufferedReader(new FileReader(transactionsFile));
			outputTransactions = new BufferedWriter(new FileWriter(transactionsFile, true));
			recoverTransactions();

		} catch (IOException e) {
			System.err.println("ERROR: Creation of databases failed. Aborting...");
			e.printStackTrace();
			System.exit(1);
		}
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
		System.out.println("Generating nonce for user " + userId);
		String nonce = cryptoUtils.generateCNonce();
		nonceList.put(userId, nonce);
		return nonce;
	}

	/*
	 * Invoked when a user wants to sell a particular good
	 */
	@Override
	public Result intentionToSell(String userId, String goodId, String cnonce, byte[] signature)
		throws RemoteException {
		if (userId == null || goodId == null || cnonce == null || signature == null) {
			throw new NullPointerException();
		}

		System.out
			.println("------ INTENTION TO SELL ------\n" + "User: " + userId + "\tGood: " + goodId);

		Good good;
		String data = nonceList.get(userId) + cnonce + userId + goodId;

		// verifies if good exists, user owns good, good is not already for sale and
		// signature is valid
		if ((good = goodsList.get(goodId)) != null && good.getUserId().equals(userId)
			&& !goodsToSell.contains(good.getGoodId()) && cryptoUtils
			.verifySignature(userId, data, signature)) {
			goodsToSell.add(good.getGoodId());
			sellingListUpdate(good.getGoodId());
			System.out.println("Result: TRUE");
			System.out.println("-------------------------------\n");
			return new Result(true, cnonce, cryptoUtils.signMessage(data + "true"));
		}

		System.out.println("Result: FALSE");
		System.out.println("-------------------------------\n");
		return new Result(false, cnonce, cryptoUtils.signMessage(data + "false"));

	}

	/*
	 * Invoked when a user wants to check if the good is for sale and who the
	 * current owner is
	 */
	@Override
	public Result stateOfGood(String userId, String cnonce, String goodId, byte[] signature)
		throws RemoteException {

		if (userId == null || cnonce == null || goodId == null || signature == null) {
			throw new NullPointerException();
		}

		System.out.println("------ STATE OF GOOD ------\nUser: " + userId + "\tGood: " + goodId);

		String data = nonceList.get(userId) + cnonce + userId + goodId;

		Good good;
		if ((good = goodsList.get(goodId)) != null && cryptoUtils
			.verifySignature(userId, data, signature)) {
			boolean status = goodsToSell.contains(goodId);
			System.out.println("Owner: " + good.getUserId() + "\nFor Sale: " + status);
			System.out.println("---------------------------\n");
			return new Result(good.getUserId(), status, cnonce,
				cryptoUtils.signMessage(data + status));
		}
		System.out.println("ERROR getting state of good");
		System.out.println("---------------------------\n");
		return new Result(false, cnonce, cryptoUtils.signMessage(data + "false"));

	}

	/*
	 * Invoked when a user invokes buyGood in seller, it is an official transfer of goods if the notary verifies that
	 * every parameter is correct
	 */
	@Override
	public Transfer transferGood(String sellerId, String buyerId, String goodId, String cnonce,
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
			&& goodsToSell.contains(goodId)
			&& cryptoUtils.verifySignature(sellerId, data, signature)) {
			good.setUserId(buyerId);
			goodsList.put(goodId, good);
			goodsToSell.remove(goodId);
			saveTransfer(sellerId, buyerId, goodId);
			removeSelling(goodId);

			// Sign transfer with Cartao Do Cidadao
			try {
				String toSign = transferId + buyerId + sellerId + goodId;
				System.out.println("Verify: " + toSign);
				Transfer transfer = new Transfer(transferId++, buyerId, sellerId, goodId,
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

	private byte[] signWithCC(String string) throws PKCS11Exception {
		System.out.println("Signing with Cartao Do Cidadao");
		return pkcs11.C_Sign(p11_session, string.getBytes(Charset.forName("UTF-8")));
	}

	private void recoverSellingList() throws IOException {
		System.out.println("Recovering selling list");
		String line;
		while ((line = inputSellings.readLine()) != null) {
			System.out.println("--> " + line);
			System.out.println("GoodId: " + line);
			goodsToSell.add(line);
		}

	}

	private void recoverTransactions() throws IOException {
		System.out.println("Recovering transactions");
		String line;
		String[] splitLine;
		Good good;

		while ((line = inputTransactions.readLine()) != null) {
			splitLine = line.split(";");

			//checks if line is well constructed
			if (splitLine.length != 3 || splitLine[0] == null || splitLine[1] == null
				|| splitLine[2] == null) {
				System.err.println("ERROR: Recovering line failed. Ignoring line...");
				continue;
			}

			System.out.println(
				"Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: " + splitLine[2]);
			good = goodsList.get(splitLine[2]);
			good.setUserId(splitLine[1]);
			goodsList.put(splitLine[2], good);
		}


	}

	private void saveTransfer(String sellerId, String buyerId, String goodId) {
		try {
			outputTransactions.write(sellerId + ";" + buyerId + ";" + goodId + "\n");
			outputTransactions.flush();
		} catch (IOException e) {
			System.err.println("ERROR: writing to TRANSACTIONS file failed");
		}
	}

	private void sellingListUpdate(String goodId) {
		try {
			outputSellings.write(goodId + "\n");
			outputSellings.flush();
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
		//Remover given goodId from selling list
		File tempFile = new File(TEMPFILE);
		String currentLine;
		BufferedWriter tempWriter = new BufferedWriter(new FileWriter(tempFile));
		while ((currentLine = inputSellings.readLine()) != null) {
			// trim newline when comparing with lineToRemove
			String trimmedLine = currentLine.trim();
			if (trimmedLine.equals(goodId)) {
				continue;
			}
			tempWriter.write(currentLine + ("\n"));
		}
		tempWriter.close();
		tempFile.renameTo(sellingListFile);
	}

	private void printGoods() {
		System.out.println("----- LIST OF GOODS -----");
		for (String id : goodsList.keySet()) {
			System.out.println(goodsList.get(id).getUserId() + " - " + id);
		}
		System.out.println("-------------------------\n");
	}

	private void printSellingList() {
		for (String entry : goodsToSell) {
			System.out.println("Good " + entry + " is selling");
		}
	}

	public void stop() {
		try {
			inputTransactions.close();
			outputTransactions.close();
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

	private void createDatabases() throws IOException {
		// creates file with all transactions and file with selling list
		transactionsFile = new File(TRANSACTIONSPATH);
		if (!transactionsFile.exists()) {
			transactionsFile.createNewFile();
			System.out.println("Creating new TRANSACTIONS file");
		}

		sellingListFile = new File(SELLINGLISTPATH);
		if (!sellingListFile.exists()) {
			sellingListFile.createNewFile();
			System.out.println("Creating new SELLING LIST file");
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
		return getCertificateInBytes(0); // certificado 0 no Cartao do Cidadao eh o de autenticacao
	}

	// Returns the n-th certificate, starting from 0
	private static byte[] getCertificateInBytes(int n) {
		byte[] certificate_bytes = null;
		try {
			PTEID_Certif[] certs = pteid.GetCertificates();
			int i = 0;

			certificate_bytes = certs[n].certif; // gets the byte[] with the n-th certif

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
	public X509Certificate getCertificate() throws RemoteException {
		return certificate;
	}

	@Override
	public X509Certificate connectToNotary(String userId, String cnounce,
		X509Certificate userCert, byte[] signature)
		throws RemoteException, InvalidSignatureException {
		// TODO save user certificate and throw exception
		certList.put(userId, userCert);
		String toVerify = nonceList.get(userId) + cnounce + userId;
		if (cryptoUtils.verifySignature(userId, toVerify, signature)) {
			return getCertificate(); //TODO
		} else {
			throw new InvalidSignatureException();
		}
	}

	@Override
	public Result getGoodsFromUser(String userId, String cnonce, byte[] signature) throws RemoteException, InvalidSignatureException {
		//verify sender
		String toVerify = nonceList.get(userId) + cnonce + userId;
		if(!cryptoUtils.verifySignature(userId, toVerify, signature))
			throw new InvalidSignatureException();
		
		//process
		TreeMap<String, Boolean> map = new TreeMap<>();
		for (Good good : goodsList.values()) {
			if (good.getUserId().equals(userId)) {
				map.put(good.getGoodId(), goodsToSell.contains(good.getGoodId()));
			}
		}
		//return result signed
		String data = toVerify + map.hashCode();
		return new Result(null, false, map, cnonce, cryptoUtils.signMessage(data));
	}
}
