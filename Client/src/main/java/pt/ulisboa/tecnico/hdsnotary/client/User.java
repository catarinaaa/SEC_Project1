package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
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

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class User extends UnicastRemoteObject implements UserInterface {
	
	private static final String DIGEST_ALGORITHM = "SHA-256";
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String ALGORITHM = "RSA";
	private static final String NOTARYPUBKEYPATH = "Server/storage/notaryPublicKey.txt";
	private static final String NOTARY_ID = "Notary";

	private final String id;
	private final String user2;
	private final String user3;
	private UserInterface remoteUser2 = null;
	private UserInterface remoteUser3 = null;
	// List of all goods possessed
	private Map<String, Boolean> goods;
	// Instance of remote Notary Object
	private NotaryInterface notary = null;

	private SecureRandom secRandom = new SecureRandom();
	private String keysPath; // KeyStore location
	private String password; // KeyStore password
	PrivateKey privateKey;
	PublicKey publicKey;
	
	private Map<String, String> nounceList = new HashMap<>();

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
	public String getNounce(String userId, byte[] signature) {
		
		String nounce = generateCNounce();
		nounceList.put(userId, nounce);
		return nounce;
	}
	
	@Override
	public Boolean buyGood(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException {

		String nounceToNotary = generateCNounce();
		String data = notary.getNounce(this.id) + cnounce + this.id + userId + goodId;
		byte[] signedHashedData = signMessage(data);

		Result result = notary.transferGood(this.getId(), userId, goodId, nounceToNotary, signedHashedData);

//		System.out.println("> " + data + result.getResult());

		if (verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
			System.out.println("Signature verified! Notary confirmed buy good");
			goods.put(goodId, false);
			return result.getResult();
		}
		else {
			System.err.println("ERROR: Signature does not verify");
			return false;
		}
	}
	
	public boolean buying(String goodId) throws RemoteException {
		Result stateOfGood = stateOfGood(goodId);
		if (stateOfGood == null || false == stateOfGood.getResult()) {
			System.out.println("Good is not up for sale");
			return false;
		}
		else {
			String seller = stateOfGood.getUserId();
			
			if(remoteUser2 == null || remoteUser3 == null) {
				lookUpUsers();
			}
			
			if(seller.equals(user2) && remoteUser2 != null) {
				
				String nounce = remoteUser2.getNounce(this.id, signMessage(this.id));
				String cnounce = generateCNounce();
				nounceList.put(user2, cnounce);
				String toSign = nounce + cnounce + this.id + goodId;
				return remoteUser2.buyGood(this.id, goodId, cnounce, signMessage(toSign));
			}
			else if(seller.equals(user3) && remoteUser3 != null) {
				String nounce = remoteUser3.getNounce(this.id, signMessage(this.id));
				String cnounce = generateCNounce();
				nounceList.put(user3, cnounce);
				String toSign = nounce + cnounce + this.id + goodId;
				return remoteUser3.buyGood(this.id, goodId, cnounce, signMessage(toSign));
			}
			
			return false;
		}
	}

	public boolean intentionSell(String goodId) {
		try {
			String nounce = notary.getNounce(this.id);
			String cnounce = generateCNounce();
			String data = nounce + cnounce + this.id + goodId;
			Result result = notary.intentionToSell(this.id, goodId, cnounce, signMessage(data));
			
			if (verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
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
	
	public Result stateOfGood(String goodId) {
		try {
			String cnounce = generateCNounce();
			String data = notary.getNounce(this.id) + cnounce + this.id + goodId;
	
			Result result = notary.stateOfGood(this.getId(), cnounce, goodId, signMessage(data));
	
	//		System.out.println("> " + data + result.getResult());
	
			if (verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed state of good");
				return result;
			}
			else {
				System.out.println("Signature does not verify!");
				return result;
			}
		} catch(RemoteException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	public void listGoods() {
		for (String goodId: goods.keySet()){
			Boolean value = goods.get(goodId);
            System.out.println(goodId + "-->" + value);
		} 
	}
	
	private void lookUpUsers() {
		try {
			remoteUser2 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser2());
			remoteUser3 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser3());
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.err.println("ERROR looking up user");
		}
		
	}

	private String generateCNounce() {
		return new BigInteger(256, secRandom).toString();
	}
		
	private boolean verifySignature(String id, String toVerify, byte[] signature) {
		try {

			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
			sig.initVerify(getStoredCert(id));

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

	private byte[] signMessage(String msg) {
		byte[] array = hashMessage(msg);
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
