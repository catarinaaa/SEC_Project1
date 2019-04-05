package pt.ulisboa.tecnico.hdsnotary.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;
import java.util.TreeMap;
import pt.ulisboa.tecnico.hdsnotary.library.*;
import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;

public class NotaryImpl extends UnicastRemoteObject implements NotaryInterface, Serializable {

	private static final String ALGORITHM = "SHA1withDSA";
	private static final long serialVersionUID = 1L;
	private final static String PATH = "storage/database.txt";

	// Singleton
	private static NotaryImpl instance = null;

	// To be changed **********************
	private Random random = new Random();
	// ************************************

	// List containing all goods
	private TreeMap<String, Good> goodsList = new TreeMap<>();

	// List containing goods that are for sale
	private ArrayList<String> goodsToSell = new ArrayList<String>();

	// List containing nounces for security
	private TreeMap<String, String> nounceList = new TreeMap<>();

	private File file = null;
	private BufferedReader input = null;
	private BufferedWriter output = null;

	private PrivateKey privateKey = null;
	private PublicKey publicKey = null;

	private Signature signature;

	protected NotaryImpl() throws RemoteException {
		super();
		populateList();

		try {
			file = new File(PATH);
			if (!file.exists()) {
				file.createNewFile();
				System.out.println("Creating new file");
			}

			// generate public/private keys
			// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			// !!!!!! IMPLEMENT CARTAO DO CIDADAO !!!!!!
			// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			KeyPair pair = generateKeys();

			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
			writePublicKeyToFile();
			// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

			signature = Signature.getInstance(ALGORITHM);
			signature.initSign(privateKey);

			// Missing recovering goodsToSell list
			// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			input = new BufferedReader(new FileReader(file));
			output = new BufferedWriter(new FileWriter(file, true));
			recoverTransactions();
			printGoods();
			
			setupCititzenCard();

		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException | CertificateException | PteidException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	public static NotaryImpl getInstance() {
		if (instance == null) {
			try {
				instance = new NotaryImpl();
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
		BigInteger nounce = new BigInteger(256, random);
		nounceList.put(userId, nounce.toString());
		return nounce.toString();
	}

	@Override
	public Result intentionToSell(String userId, String goodId, String cnounce, byte[] signature)
			throws RemoteException {

		String toHash = "";

		try {

			toHash = nounceList.get(userId) + cnounce + userId + goodId;
			System.out.println(toHash);
			if (!verifySignatureAndHash(toHash, signature, userId))
				return new Result(false, cnounce, signMessage(toHash + "false"));

			Good good;

			if ((good = goodsList.get(goodId)) != null) {
				if (good.getUserId().equals(userId) && !goodsToSell.contains(good.getGoodId())) {
					goodsToSell.add(good.getGoodId());
					return new Result(true, cnounce, signMessage(toHash + "true"));
				}
			}

			return new Result(false, cnounce, signMessage(toHash + "false"));

		} catch (Exception e) {
			e.printStackTrace();
			return new Result(false, cnounce, signMessage(toHash + "false"));
		}

	}

	@Override
	public State stateOfGood(String userId, String cnounce, String goodId) throws RemoteException {
		Good good;
		if ((good = goodsList.get(goodId)) != null) {
			boolean status = goodsToSell.contains(goodId);
			String toSign = nounceList.get(userId) + cnounce + goodId + good.getUserId() + status;

			return new State(good.getUserId(), status, cnounce, signMessage(toSign));
		} else
			return null;
	}

	@Override
	public Result transferGood(String sellerId, String buyerId, String goodId, String cnounce, byte[] signature)
			throws RemoteException {

		String msg = nounceList.get(sellerId) + cnounce + sellerId + buyerId + goodId;

		if (!verifySignatureAndHash(msg, signature, sellerId)) {
			return new Result(false, cnounce, signMessage(msg + "false"));
		}

		Good good;
		if ((good = goodsList.get(goodId)) != null) {
			if (good.getUserId().equals(sellerId) && goodsToSell.contains(goodId)) {
				good.setUserId(buyerId);
				goodsList.put(goodId, good);
				goodsToSell.remove(goodId);
				saveTransfer(sellerId, buyerId, goodId);
				printGoods();
				System.out.println(msg + "true");
				return new Result(true, cnounce, signMessage(msg + "true"));
			}
		}
		printGoods();
		return new Result(false, cnounce, signMessage(msg + "false"));
	}

	// ...

	private KeyPair generateKeys() throws NoSuchAlgorithmException {
		// Gerar par de chave publica e privada
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keygen.initialize(1024, random);
		KeyPair pair = keygen.generateKeyPair();
		return pair;
	}

	private void recoverTransactions() throws IOException {
		System.out.println("Recovering transactions");
		String line;
		String[] splitLine;
		Good good;
		while ((line = input.readLine()) != null) {
			splitLine = line.split(";");
			System.out.println("Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: " + splitLine[2]);
			good = goodsList.get(splitLine[2]);
			good.setUserId(splitLine[1]);
			goodsList.put(splitLine[2], good);
		}

	}

	private void saveTransfer(String sellerId, String buyerId, String goodId) {
		try {
			output.write(sellerId + ";" + buyerId + ";" + goodId + "\n");
			output.flush();
		} catch (IOException e) {
			System.out.println("Error writing to file");
			e.printStackTrace();
		}
	}

	private void populateList() {

		goodsList.put("good1", new Good("user1", "good1"));
		goodsList.put("good2", new Good("user1", "good2"));
		goodsList.put("good3", new Good("user1", "good3"));
		goodsList.put("good4", new Good("user2", "good4"));
		goodsList.put("good5", new Good("user3", "good5"));
		goodsList.put("good6", new Good("user3", "good6"));

	}

	private void printGoods() {
		for (String id : goodsList.keySet()) {
			System.out.println(goodsList.get(id).getUserId() + " - " + id);
		}
	}

	public void stop() {
		try {
			input.close();
			output.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static String bytesToHex(byte[] hash) {
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}
		return hexString.toString();
	}

	private boolean verifySignatureAndHash(String dataStr, byte[] signature, String userId) {
		try {
			String pubKeyPath = "./storage/pubKey-" + userId + ".txt";
			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			FileInputStream pubKeyStream = new FileInputStream(pubKeyPath);
			int pubKeyLength = pubKeyStream.available();
			byte[] pubKeyBytes = new byte[pubKeyLength];
			pubKeyStream.read(pubKeyBytes);
			pubKeyStream.close();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

			Signature sig = Signature.getInstance(ALGORITHM);
			sig.initVerify(publicKey);

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(dataStr.getBytes("UTF-8"));
			sig.update(hashed);
			if (sig.verify(signature)) {
				System.out.println("Hashs are the same and have not been modified");
				return true;
			} else {
				System.out.println("ERROR!");
				return false;
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private void writePublicKeyToFile() throws IOException {
		File file = new File("./storage/notaryPublicKey.txt");
		if (!file.exists()) {
			file.createNewFile();
			System.out.println("Creating new file");
		}
		FileOutputStream output = new FileOutputStream(file);
		output.write(publicKey.getEncoded());
		output.flush();
		output.close();

	}

	private byte[] signMessage(String message) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] digested = digest.digest(message.getBytes("UTF-8"));
			signature.update(digested);
			return signature.sign();
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	private void setupCititzenCard() throws PteidException, CertificateException {
		System.out.println("            //Load the PTEidlibj");
		System.out.println(System.getProperty("java.library.path"));
		System.loadLibrary("pteidlibj");
		pteid.Init(""); // Initializes the eID Lib
		pteid.SetSODChecking(false); // Don't check the integrity of the ID, address and photo (!)

		PKCS11 pkcs11;
		String osName = System.getProperty("os.name");
		String javaVersion = System.getProperty("java.version");
		System.out.println("Java version: " + javaVersion);

		java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();

		String libName = "libpteidpkcs11.so";

		// access the ID and Address data via the pteidlib
		System.out.println("            -- accessing the ID  data via the pteidlib interface");

		X509Certificate cert = getCertFromByteArray(getCertificateInBytes(0));
		System.out.println("Citized Authentication Certificate " + cert);

	}
	
	//Returns the CITIZEN AUTHENTICATION CERTIFICATE
    public static byte[] getCitizenAuthCertInBytes(){
        return getCertificateInBytes(0); //certificado 0 no Cartao do Cidadao eh o de autenticacao
    }

    // Returns the n-th certificate, starting from 0
    private static  byte[] getCertificateInBytes(int n) {
        byte[] certificate_bytes = null;
        try {
            PTEID_Certif[] certs = pteid.GetCertificates();
            System.out.println("Number of certs found: " + certs.length);
            int i = 0;
	    for (PTEID_Certif cert : certs) {
                System.out.println("-------------------------------\nCertificate #"+(i++));
                System.out.println(cert.certifLabel);
            }

            certificate_bytes = certs[n].certif; //gets the byte[] with the n-th certif

            //pteid.Exit(pteid.PTEID_EXIT_LEAVE_CARD); // OBRIGATORIO Termina a eID Lib
        } catch (PteidException e) {
            e.printStackTrace();
        }
        return certificate_bytes;
    }

    public static X509Certificate getCertFromByteArray(byte[] certificateEncoded) throws CertificateException{
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificateEncoded);
        X509Certificate cert = (X509Certificate)f.generateCertificate(in);
        return cert;
    }

}
