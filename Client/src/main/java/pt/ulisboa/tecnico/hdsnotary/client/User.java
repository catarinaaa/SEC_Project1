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
import java.util.Random;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class User implements UserInterface {
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String ALGORITHM = "RSA";
	private static final String NOTARYPUBKEYPATH = "Server/storage/notaryPublicKey.txt";

	private final String id;
	// List of all goods possessed
	private ArrayList<Good> goods;
	// Instance of remote Notary Object
	private NotaryInterface notary = null;
	
	private Random random = new Random();
	private String keysPath; //KeyStore location
	private String password; //KeyStore password
	PrivateKey privateKey;
	PublicKey publicKey;

	public User(String id, NotaryInterface notary) {
		super();
		
		this.id = id;
		this.notary = notary;
		this.keysPath = "Client/storage/" + id + ".p12";
		this.password = id + "1234";
		
		try {
			this.privateKey = getStoredKey();
		} catch (KeyStoreException e) {
	    	System.err.println("ERROR: KeyStore failed");
	    	System.exit(1);	  
		}
		System.out.println("Initializing user " + id);
		
	}

	public String getId() {
		return id;
	}

	public ArrayList<Good> getGoods() {
		return goods;
	}

	@Override
	public Boolean buyGood(String userId, String goodId) throws RemoteException {

		String cnounce = generateCNounce();
		String data = notary.getNounce(this.id) + cnounce + this.id + userId + goodId;
		byte[] hashedData = hashMessage(data);
		byte[] signedHashedData = signByteArray(hashedData);

		Result result = notary.transferGood(this.getId(), userId, goodId, cnounce, signedHashedData);

		System.out.println("> " + data + result.getResult());

		if (verifySignature(data + result.getResult(), result.getSignature()))
			return result.getResult();
		else {
			System.err.println("ERROR: Signature does not verify");
			return false;
		}
	}

	public void test() throws Exception {
		byte[] data = "Hey, this was signed".getBytes();
		Signature dsaForSign = Signature.getInstance("SHA1withDSA");
		dsaForSign.initSign(privateKey);
		dsaForSign.update(data);
		byte[] signature = dsaForSign.sign();

		dsaForSign.initVerify(publicKey);
		dsaForSign.update(data);
		System.out.println("> " + dsaForSign.verify(signature));

	}

	public boolean sell(String goodId) {
		try {
			String nounce = notary.getNounce(this.id);
			String cnounce = generateCNounce();
			String str = nounce + cnounce + this.id + goodId;
			System.out.println(str);
			byte[] dataDigested = hashMessage(str);
			byte[] hashSigned = signByteArray(dataDigested);

			System.out.println("Intention > " + notary.intentionToSell(this.id, goodId, cnounce, hashSigned));

		} catch (RemoteException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
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

		} catch (NoSuchAlgorithmException | SignatureException
				| InvalidKeyException | KeyStoreException e) {
			System.err.println("Exception caught while verifying signature!");
			e.printStackTrace();
			return false;
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

	private byte[] hashMessage(String msg) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(msg.getBytes("UTF-8"));
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	private byte[] signByteArray(byte[] array) {
		Signature dsaForSign;
		try {
			dsaForSign = Signature.getInstance(SIGNATURE_ALGORITHM);
			dsaForSign.initSign(privateKey);
			dsaForSign.update(array);
			return dsaForSign.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	private PrivateKey getStoredKey() throws KeyStoreException {
		//Load KeyStore
	    KeyStore ks = KeyStore.getInstance("pkcs12");
	    KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
	    FileInputStream fis = null;
	    PrivateKey priKey= null;
	    try {
	        fis = new FileInputStream(new File(keysPath));
	        ks.load(fis, password.toCharArray());
	        
		    //Load PrivateKey
		    PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(this.id, protParam);
		    priKey = pkEntry.getPrivateKey();
		      
	        if (fis != null) {
	            fis.close();
	        } 
	    } catch (FileNotFoundException | CertificateException e) {
	    	System.err.println("ERROR: KeyStore/certificate of user" + id + " not found");
	    	System.exit(1);
	    } catch(UnrecoverableEntryException | IOException e) {
	    	System.err.println("ERROR: Wrong password of KeyStore");
	    	System.exit(1);
	    } catch(NoSuchAlgorithmException e) {
	    	System.err.println("ERROR: Wrong algorithm in KeyStore");
	    	System.exit(1);	    	
	    }
	    return priKey;
	}
	
	// Gets notary certificate
	private X509Certificate getStoredCert(String NotaryId) throws KeyStoreException {
		//Load KeyStore
	    KeyStore ks = KeyStore.getInstance("pkcs12");
	    FileInputStream fis = null;
	    X509Certificate cert = null;
	    try {
	        fis = new FileInputStream(new File("Server/storage/Notary.p12"));
	        ks.load(fis, NotaryId.toCharArray());
	        
		    //Load certificate
		    cert = (X509Certificate) ks.getCertificate(NotaryId);
		      
	        if (fis != null) {
	            fis.close();
	        } 
	    } catch (FileNotFoundException | CertificateException e) {
	    	System.err.println("ERROR: KeyStore/certificate of " + NotaryId + " not found");
	    	System.exit(1);
	    } catch(IOException e) {
	    	System.err.println("ERROR: Wrong password of KeyStore");
	    	System.exit(1);
	    } catch(NoSuchAlgorithmException e) {
	    	System.err.println("ERROR: Wrong algorithm in KeyStore");
	    	System.exit(1);	    	
	    }
	    return cert;
	}
	
}
