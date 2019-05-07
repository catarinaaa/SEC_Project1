package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Scanner;

public class CryptoUtilities {
	
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

	private SecureRandom secRandom = new SecureRandom();
	
	private PrivateKey privateKey;
	private final String userId;
	private final String keysPath;
	private final String password;
	
	private HashMap<String, X509Certificate> certList = new HashMap<String, X509Certificate>();
	
	Scanner scanner = new Scanner(System.in);
	
	public CryptoUtilities(String id, String keysPath, String password) throws KeyStoreException {
		this.userId = id;
		this.keysPath = keysPath;
		this.password = password;
		
		int count = 0;
		while(count <= 5) {
			try {
				this.privateKey = getStoredKey();
				break;
			} catch (KeyStoreException e) {
				System.out.println("Check if the right keyStore is in folder storage and press Enter");
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

	public void addCertToList(String id, X509Certificate cert) {
		certList.put(id, cert);
	}
	
	public Boolean containsCert(String id) {
		return certList.containsKey(id);	
	}
	
	public boolean verifySignature(String id, String toVerify, byte[] signature) {
		return verifySignature(id, toVerify, signature, null);
	}

	public boolean verifySignature(String id, String toVerify, byte[] signature, X509Certificate cert) {
		try {

			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);

			if(cert == null)
				sig.initVerify(certList.get(id));
			else
				sig.initVerify(cert);

			sig.update(toVerify.getBytes(Charset.forName("UTF-8")));
			if (sig.verify(signature)) {
				return true;
			}
				
			else {
				return false;
			}
				
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			System.err.println("ERROR: Exception caught while verifying signature");
			e.printStackTrace();
			return false;
		}
	}

	public byte[] signMessage(String msg) {
		Signature rsaForSign;
		try {
			rsaForSign = Signature.getInstance(SIGNATURE_ALGORITHM);
			rsaForSign.initSign(privateKey);
			rsaForSign.update(msg.getBytes(Charset.forName("UTF-8")));
			return rsaForSign.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}
	
	public PrivateKey getStoredKey() throws KeyStoreException {
		System.out.println("Keystore: " + this.userId);
		// Load KeyStore
		KeyStore ks = KeyStore.getInstance("pkcs12");
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
		FileInputStream fis = null;
		PrivateKey priKey = null;
		try {
			fis = new FileInputStream(new File(keysPath));
			ks.load(fis, password.toCharArray());

			// Load PrivateKey
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(userId, protParam);
			priKey = pkEntry.getPrivateKey();

			if (fis != null) {
				fis.close();
			}
		} catch (FileNotFoundException | CertificateException e) {
			System.err.println("ERROR: KeyStore/certificate of user" + userId + " not found");
		} catch (UnrecoverableEntryException | IOException e) {
			System.err.println("ERROR: Wrong password of KeyStore");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Wrong algorithm in KeyStore");
		}
		return priKey;
	}
	
	// Gets stored certificate
	public X509Certificate getStoredCert(String userId){

		// Load KeyStore
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("pkcs12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		FileInputStream fis = null;
		X509Certificate cert = null;
		try {
			fis = new FileInputStream(new File(keysPath));
			ks.load(fis, password.toCharArray());

			// Load certificate
			cert = (X509Certificate) ks.getCertificate(userId);

			if (fis != null) {
				fis.close();
			}
		} catch (FileNotFoundException | CertificateException | KeyStoreException e) {
			System.err.println("ERROR: KeyStore/certificate of " + userId + " not found");
		} catch (IOException e) {
			System.err.println("ERROR: Wrong password of KeyStore");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Wrong algorithm in KeyStore");
		}

		return cert;
	}
	
	public X509Certificate getStoredCert(){

		// Load KeyStore
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("pkcs12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		FileInputStream fis = null;
		X509Certificate cert = null;
		try {
			fis = new FileInputStream(new File(keysPath));
			ks.load(fis, password.toCharArray());

			// Load certificate
			cert = (X509Certificate) ks.getCertificate(userId);

			if (fis != null) {
				fis.close();
			}
		} catch (FileNotFoundException | CertificateException | KeyStoreException e) {
			System.err.println("ERROR: KeyStore/certificate of " + userId + " not found");
		} catch (IOException e) {
			System.err.println("ERROR: Wrong password of KeyStore");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Wrong algorithm in KeyStore");
		}

		return cert;
	}
	
	public String generateCNonce() {
		return new BigInteger(256, secRandom).toString();
	}

}
