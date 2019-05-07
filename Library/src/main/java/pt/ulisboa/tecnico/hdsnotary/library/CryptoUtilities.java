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
import java.sql.Timestamp;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Scanner;

public class CryptoUtilities {
	
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static final int MAX_DELAY_TIME = 30*1000; //30 seconds

	private SecureRandom secRandom = new SecureRandom();
	
	private PrivateKey privateKey;
	private final String userId;
	private final String keysPath;
	private final String password;
	
	private HashMap<String, String> passwordsKeyStores = new HashMap<>();
	private HashMap<String, String> certPathsList = new HashMap<>();
	private HashMap<String, X509Certificate> certList = new HashMap<String, X509Certificate>();
	
	Scanner scanner = new Scanner(System.in);
	
	public CryptoUtilities(String id, String keysPath, String password) throws KeyStoreException {
		this.userId = id;
		this.keysPath = keysPath;
		this.password = password;
		
		this.passwordsKeyStores.put("Alice", "Alice1234");
		this.passwordsKeyStores.put("Bob", "Bob1234");
		this.passwordsKeyStores.put("Charlie", "Charlie1234");
		this.passwordsKeyStores.put("Notary", "Notary");
		this.passwordsKeyStores.put("Notary1", "Notary1");
		this.passwordsKeyStores.put("Notary2", "Notary2");
		this.passwordsKeyStores.put("Notary3", "Notary3");
		this.passwordsKeyStores.put("Notary4", "Notary4");
		this.passwordsKeyStores.put("CertCC", "Notary");
		this.certPathsList.put("Alice", "Client/storage/Alice.p12");
		this.certPathsList.put("Bob", "Client/storage/Bob.p12");
		this.certPathsList.put("Charlie", "Client/storage/Charlie.p12");
		this.certPathsList.put("Notary1", "Server/storage/Notary1.p12");
		this.certPathsList.put("Notary2", "Server/storage/Notary2.p12");
		this.certPathsList.put("Notary3", "Server/storage/Notary3.p12");
		this.certPathsList.put("Notary4", "Server/storage/Notary4.p12");
		this.certPathsList.put("Notary", "Server/storage/Notary.p12");
		this.certPathsList.put("CertCC", "Server/storage/CertCC.p12");
		
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
	
//	public CryptoUtilities(String id, String keysPath, String password) throws KeyStoreException {
//
//
//		this.userId = id;
//		this.keysPath = keysPath;
//		this.password = password;
//
//		this.passwordsKeyStores.put("Alice", "Alice1234");
//		this.passwordsKeyStores.put("Bob", "Bob1234");
//		this.passwordsKeyStores.put("Charlie", "Charlie1234");
//		this.passwordsKeyStores.put("Notary", "Notary");
//		this.passwordsKeyStores.put("CertCC", "Notary");
//		this.certPathsList.put("Alice", "Client/storage/Alice.p12");
//		this.certPathsList.put("Bob", "Client/storage/Bob.p12");
//		this.certPathsList.put("Charlie", "Client/storage/Charlie.p12");
//		this.certPathsList.put("Notary", "Server/storage/Notary.p12");
//		this.certPathsList.put("CertCC", "Server/storage/CertCC.p12");
//
//		int count = 0;
//		while(count <= 5) {
//			try {
//				this.privateKey = getStoredKey();
//				break;
//			} catch (KeyStoreException e) {
//				System.out.println("Check if the right keyStore is in folder storage and press Enter");
//				scanner.nextLine();
//				count++;
//			} finally {
//				if (count == 5) {
//					System.err.println("ERROR: Number of tries exceeded. Aborting...");
//					scanner.close();
//					System.exit(1);
//				}
//			}
//		}
//
//
//		this.privateKey = getStoredKey();
//	}

	public boolean verifySignature(String id, String toVerify, byte[] signature) {
		return verifySignature(id, toVerify, signature, null);
	}


	public boolean verifySignature(String id, String toVerify, byte[] signature, X509Certificate cert) {
		try {

			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);

			if(cert == null)
				sig.initVerify(getStoredCert(id));
			else
				sig.initVerify(cert);

			sig.update(toVerify.getBytes(Charset.forName("UTF-8")));
			if (sig.verify(signature)) {
				return true;
			}
				
			else {
				return false;
			}
				

		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | KeyStoreException e) {
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
	
	// Gets notary certificate
	public X509Certificate getStoredCert(String userId) throws KeyStoreException {

		// Load KeyStore
		String password = passwordsKeyStores.get(userId);
		String certPath = certPathsList.get(userId);

		KeyStore ks = KeyStore.getInstance("pkcs12");
		FileInputStream fis = null;
		X509Certificate cert = null;
		try {
			fis = new FileInputStream(new File(certPath));
			ks.load(fis, password.toCharArray());

			// Load certificate
			cert = (X509Certificate) ks.getCertificate(userId);

			if (fis != null) {
				fis.close();
			}
		} catch (FileNotFoundException | CertificateException e) {
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
