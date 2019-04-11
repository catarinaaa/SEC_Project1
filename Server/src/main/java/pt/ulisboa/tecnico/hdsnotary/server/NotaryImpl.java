package pt.ulisboa.tecnico.hdsnotary.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.TreeMap;

import pt.gov.cartaodecidadao.PteidException;
import pt.ulisboa.tecnico.hdsnotary.library.CryptoUtilities;
import pt.ulisboa.tecnico.hdsnotary.library.Good;
import pt.ulisboa.tecnico.hdsnotary.library.NotaryInterface;
import pt.ulisboa.tecnico.hdsnotary.library.Result;
import pt.ulisboa.tecnico.hdsnotary.library.Transfer;
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

	private final static String id = "Notary";
	private final static String keysPath = "Server/storage/Notary.p12";
	private final static String certPath = "Server/storage/CertCC.p12";
	private final static String TRANSACTIONSPATH = "Server/storage/transactions.txt";
	private final static String SELLINGLISTPATH = "Server/storage/selling.txt";

	// Singleton
	private static NotaryImpl instance = null;

	private SecureRandom secRandom = new SecureRandom();

	// List containing all goods
	private TreeMap<String, Good> goodsList = new TreeMap<>();

	// List containing goods that are for sale
	private ArrayList<String> goodsToSell = new ArrayList<String>();

	// List containing nounces for security
	private TreeMap<String, String> nounceList = new TreeMap<>();

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

	private boolean useCC = true;

	private CryptoUtilities cryptoUtils;

	public NotaryImpl(boolean cc) throws RemoteException, KeyStoreException {
		super();
		populateList();
		Scanner scanner = new Scanner(System.in);
		this.useCC = cc;

		cryptoUtils = new CryptoUtilities(this.id, this.keysPath, this.id);

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
			System.err.println("ERROR: creation of Notary failed. Aborting...");
			e.printStackTrace();
			System.exit(1);
		}
	}

	public static NotaryImpl getInstance() throws KeyStoreException {
		if (instance == null) {
			try {
				instance = new NotaryImpl(false);
			} catch (RemoteException e) {
				e.printStackTrace();
				System.exit(1);
			}
		}
		return instance;
	}

	// Override NotaryInterface functions
	@Override
	public String getNounce(String userId) throws RemoteException {
		BigInteger nounce = new BigInteger(256, secRandom);
		nounceList.put(userId, nounce.toString());
		return nounce.toString();
	}

	@Override
	public Result intentionToSell(String userId, String goodId, String cnounce, byte[] signature)
			throws RemoteException {
		System.out.println("------ INTENTION TO SELL ------\n" + "User: " + userId + "\tGood: " + goodId);

		String data = "";
		try {

			Good good;
			data = nounceList.get(userId) + cnounce + userId + goodId;

			// verifies good exists, user owns good, good is not already for sale and
			// signature is valid
			if ((good = goodsList.get(goodId)) != null && good.getUserId().equals(userId)
					&& !goodsToSell.contains(good.getGoodId())
					&& cryptoUtils.verifySignature(userId, data, signature)) {
				goodsToSell.add(good.getGoodId());
				sellingListUpdate(userId, good.getGoodId());
				System.out.println("Result: YES\n");
				return new Result(true, cnounce, cryptoUtils.signMessage(data + "true"));
			}

			System.out.println("Result: NO\n");
			return new Result(false, cnounce, cryptoUtils.signMessage(data + "false"));

		} catch (Exception e) {
			System.err.println("ERROR: Exception caught");
			System.out.println("Result: NO\n");
			return new Result(false, cnounce, cryptoUtils.signMessage(data + "false"));
		}

	}

	@Override
	public Result stateOfGood(String userId, String cnounce, String goodId, byte[] signature) throws RemoteException {
		System.out.println("------ STATE OF GOOD ------\nUser: " + userId + "\tGood: " + goodId);

		String data = nounceList.get(userId) + cnounce + userId + goodId;
		System.out.println("DATA: " + data);
		try {
			Good good;
			if ((good = goodsList.get(goodId)) != null && cryptoUtils.verifySignature(userId, data, signature)) {
				boolean status = goodsToSell.contains(goodId);
				System.out.println("Result: " + good.getUserId() + "\nFor Sale: " + status + "\n");
				return new Result(good.getUserId(), status, cnounce, cryptoUtils.signMessage(data + status));
			}
			return new Result(false, cnounce, cryptoUtils.signMessage(data + "false"));
		} catch (Exception e) {
			e.printStackTrace();
			return new Result(false, cnounce, cryptoUtils.signMessage(data + "false"));
		}

	}

	@Override
	public Result transferGood(String sellerId, String buyerId, String goodId, String cnounce, byte[] signature)
			throws RemoteException {
		System.out.println("------ TRANSFER GOOD ------");

		System.out.println("Seller > " + sellerId);
		System.out.println("Buyer > " + buyerId);
		System.out.println("Good > " + goodId);

		String data = nounceList.get(sellerId) + cnounce + sellerId + buyerId + goodId;
		Good good;
		
		System.out.println("Data: " + data);
		
		if ((good = goodsList.get(goodId)) != null && good.getUserId().equals(sellerId) && goodsToSell.contains(goodId)
				&& cryptoUtils.verifySignature(sellerId, data, signature)) {
			good.setUserId(buyerId);
			goodsList.put(goodId, good);
			goodsToSell.remove(goodId);
			saveTransfer(sellerId, buyerId, goodId);
			printGoods();
			try {
				Transfer transfer = new Transfer(transferId++, buyerId, sellerId, goodId,
						useCC ? signWithCC(transferId + buyerId + sellerId + goodId) : null);
				System.out.println("Result: YES\n");
				return new Result(true, transfer, cnounce, cryptoUtils.signMessage(data + "true"));
			} catch (UnsupportedEncodingException | PKCS11Exception e) {
				System.err.println("ERROR: Signing with CC not possible");
				System.out.println("Result: NO\n");
				e.printStackTrace();
				return new Result(false, cnounce, cryptoUtils.signMessage(data + "false"));
			}

		}
		printGoods();
		System.out.println("Result: NO\n");
		return new Result(false, cnounce, cryptoUtils.signMessage(data + "false"));
	}
	
	public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b));
		   return sb.toString();
	}

	// ...

	private byte[] signWithCC(String string) throws UnsupportedEncodingException, PKCS11Exception {
		return pkcs11.C_Sign(p11_session, string.getBytes("UTF-8"));
	}

	private void recoverSellingList() throws IOException {
		System.out.println("Recovering selling list");
		String line;
		String[] splitLine;
		while ((line = inputSellings.readLine()) != null) {
			System.out.println("--> " + line);
			splitLine = line.split(";");
			System.out.println("Seller: " + splitLine[0] + " GoodId: " + splitLine[1]);
			goodsToSell.add(splitLine[1]);
		}

	}

	private void recoverTransactions() throws IOException {
		System.out.println("Recovering transactions");
		String line;
		String[] splitLine;
		Good good;
		while ((line = inputTransactions.readLine()) != null) {
			splitLine = line.split(";");
			System.out.println("Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: " + splitLine[2]);
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
			e.printStackTrace();
		}
	}

	private void sellingListUpdate(String sellerId, String goodId) {
		try {
			outputSellings.write(sellerId + ";" + goodId + "\n");
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

	private void printGoods() {
		for (String id : goodsList.keySet()) {
			System.out.println(goodsList.get(id).getUserId() + " - " + id);
		}
	}

	private void printSellingList() {
		for (String entry : goodsToSell)
			System.out.println("Good " + entry + " is selling");
	}

	public void stop() {
		try {
			inputTransactions.close();
			outputTransactions.close();
		} catch (IOException e) {
			System.err.println("ERROR: Closing files failed. Transactions database may not be updated");
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

	private void writeCertToKeyStore(X509Certificate cert) {
		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(id.toCharArray());
			FileOutputStream fos = new FileOutputStream(certPath);
			ks.load(null, id.toCharArray());

			ks.setCertificateEntry("CC", cert);

			ks.store(fos, id.toCharArray());

			if (fos != null) {
				fos.close();
			}
		} catch (FileNotFoundException | CertificateException e) {
			System.err.println("ERROR: KeyStore/certificate of user" + id + " not found");
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			System.err.println("ERROR: Wrong password of KeyStore");
			System.exit(1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Wrong algorithm in KeyStore");
			System.exit(1);
		} catch (KeyStoreException e) {
			System.err.println("ERROR: Error finding pkcs12");
			e.printStackTrace();
		}
	}

	private void setupCititzenCard() throws PteidException, CertificateException, pteidlib.PteidException,
			PKCS11Exception, NoSuchMethodException, SecurityException, ClassNotFoundException, IllegalAccessException,
			IllegalArgumentException, InvocationTargetException {
		System.loadLibrary("pteidlibj");
		pteid.Init(""); // Initializes the eID Lib
		pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)

		String osName = System.getProperty("os.name");
		String javaVersion = System.getProperty("java.version");

		java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();

		String libName = "libpteidpkcs11.so";

		X509Certificate cert = getCertFromByteArray(getCertificateInBytes(0));

		writeCertToKeyStore(cert);

		Class pkcs11Class;

		pkcs11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");

		if (javaVersion.startsWith("1.5.")) {
			Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance",
					new Class[] { String.class, CK_C_INITIALIZE_ARGS.class, boolean.class });
			pkcs11 = (PKCS11) getInstanceMethode.invoke(null, new Object[] { libName, null, false });
		} else {
			Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance",
					new Class[] { String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class });
			pkcs11 = (PKCS11) getInstanceMethode.invoke(null,
					new Object[] { libName, "C_GetFunctionList", null, false });
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
		mechanism.mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
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

			// pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); // OBRIGATORIO Termina a eID Lib
		} catch (pteidlib.PteidException e) {
			e.printStackTrace();
		}
		return certificate_bytes;
	}

	public static X509Certificate getCertFromByteArray(byte[] certificateEncoded) throws CertificateException {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificateEncoded);
		X509Certificate cert = (X509Certificate) f.generateCertificate(in);
		return cert;
	}

}
