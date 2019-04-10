package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class User extends UnicastRemoteObject implements UserInterface {
	
	private static final String DIGEST_ALGORITHM = "SHA-256";
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String ALGORITHM = "RSA";
	private static final String NOTARYPUBKEYPATH = "Server/storage/notaryPublicKey.txt";

	private final String id;
	private final String user2;
	private final String user3;
	// List of all goods possessed
	private Map<String, Boolean> goods;
	// Instance of remote Notary Object
	private NotaryInterface notary = null;

	private Random random = new Random();
	private String keysPath; // KeyStore location
	private String password; // KeyStore password
	PrivateKey privateKey;
	PublicKey publicKey;

	public User(String id, NotaryInterface notary, String user2, String user3) throws RemoteException {

		this.id = id;
		this.notary = notary;
		this.user2 = user2;
		this.user3 = user3;

		goods = new HashMap<String, Boolean>();
		
		System.out.println("Initializing User");

		this.keysPath = "Client/storage/" + id + ".p12";
		this.password = id + "1234";

		goods = new HashMap<String, Boolean>();

		try {
			this.privateKey = getStoredKey();
		} catch (KeyStoreException e) {
			System.err.println("ERROR: KeyStore failed");
			System.exit(1);
		}
		System.out.println("Initializing user " + id);

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

	public Map<String, Boolean> getGoods() {
		return goods;
	}

	@Override
	public Boolean buyGood(String userId, String goodId) throws RemoteException {

		String cnounce = generateCNounce();
		String data = notary.getNounce(this.id) + cnounce + this.id + userId + goodId;
		byte[] hashedData = hashMessage(data);
		byte[] signedHashedData = signByteArray(hashedData);

		Result result = notary.transferGood(this.getId(), userId, goodId, cnounce, signedHashedData);

//		System.out.println("> " + data + result.getResult());

		if (verifySignature(data + result.getResult(), result.getSignature())) {
			System.out.println("Signature verified! Notary confirmed buy good");
			goods.put(goodId, false);
			return result.getResult();
		}
		else {
			System.err.println("ERROR: Signature does not verify");
			return false;
		}
	}

	public boolean intentionSell(String goodId) {
		try {
			String nounce = notary.getNounce(this.id);
			String cnounce = generateCNounce();
			String data = nounce + cnounce + this.id + goodId;
//			System.out.println(str);
			byte[] hashedData = hashMessage(data);
			byte[] signedHashedData = signByteArray(hashedData);
			//System.out.println("Intention > " + notary.intentionToSell(this.id, goodId, cnounce, hashSigned).getResult());
			Result result = notary.intentionToSell(this.id, goodId, cnounce, signedHashedData);
			
			if (verifySignature(data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed intention to sell");
				goods.replace(goodId, false);
				return result.getResult();
			}
			else {
				System.out.println("Signature does not verify!");
				return false;
			}
		} catch (RemoteException e) {
			// TODO Auto-generated catch block
			return false;
		}
	}
	
	public boolean stateOfGood(String goodId) {
		try {
			String cnounce = generateCNounce();
			String data = notary.getNounce(this.id) + cnounce + this.id + goodId;
			byte[] hashedData = hashMessage(data);
			byte[] signedHashedData = signByteArray(hashedData);
	
			Result result = notary.stateOfGood(this.getId(), cnounce, goodId, signedHashedData);
	
	//		System.out.println("> " + data + result.getResult());
	
			if (verifySignature(data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed state of good");
				return result.getResult();
			}
			else {
				System.out.println("Signature does not verify!");
				return false;
			}
		} catch(RemoteException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public void listGoods() {
		for (String goodId: goods.keySet()){
			Boolean value = goods.get(goodId);
            System.out.println(goodId + "-->" + value);
		} 
	}
	
	private void lookUpUsers() {
		try {
			UserInterface user2 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser2());
			UserInterface user3 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser3());
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (RemoteException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotBoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	// Change to SecureRandom
	private String generateCNounce() {
		return new BigInteger(256, random).toString();
	}

	private boolean verifySignature(String toVerify, byte[] signature) {
		try {

			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
			sig.initVerify(getStoredCert("Notary"));

			byte[] hashedMsg = hashMessage(toVerify);
			sig.update(hashedMsg);
			if (sig.verify(signature))
				return true;
			else
				return false;

		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | KeyStoreException e) {
			System.err.println("Exception caught while verifying signature!");
			e.printStackTrace();
			return false;
		}

	}

	private byte[] hashMessage(String msg) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
			return digest.digest(msg.getBytes("UTF-8"));
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	private byte[] signByteArray(byte[] array) {
		Signature rsaForSign;
		try {
			rsaForSign = Signature.getInstance(SIGNATURE_ALGORITHM);
			rsaForSign.initSign(privateKey);
			rsaForSign.update(array);
			return rsaForSign.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	private PrivateKey getStoredKey() throws KeyStoreException {
		// Load KeyStore
		KeyStore ks = KeyStore.getInstance("pkcs12");
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
		FileInputStream fis = null;
		PrivateKey priKey = null;
		try {
			fis = new FileInputStream(new File(keysPath));
			ks.load(fis, password.toCharArray());

			// Load PrivateKey
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(this.id, protParam);
			priKey = pkEntry.getPrivateKey();

			if (fis != null) {
				fis.close();
			}
		} catch (FileNotFoundException | CertificateException e) {
			System.err.println("ERROR: KeyStore/certificate of user" + id + " not found");
			System.exit(1);
		} catch (UnrecoverableEntryException | IOException e) {
			System.err.println("ERROR: Wrong password of KeyStore");
			System.exit(1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Wrong algorithm in KeyStore");
			System.exit(1);
		}
		return priKey;
	}

	// Gets notary certificate
	private X509Certificate getStoredCert(String NotaryId) throws KeyStoreException {
		// Load KeyStore
		KeyStore ks = KeyStore.getInstance("pkcs12");
		FileInputStream fis = null;
		X509Certificate cert = null;
		try {
			fis = new FileInputStream(new File("Server/storage/Notary.p12"));
			ks.load(fis, NotaryId.toCharArray());

			// Load certificate
			cert = (X509Certificate) ks.getCertificate(NotaryId);

			if (fis != null) {
				fis.close();
			}
		} catch (FileNotFoundException | CertificateException e) {
			System.err.println("ERROR: KeyStore/certificate of " + NotaryId + " not found");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("ERROR: Wrong password of KeyStore");
			System.exit(1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Wrong algorithm in KeyStore");
			System.exit(1);
		}
		return cert;
	}

}
