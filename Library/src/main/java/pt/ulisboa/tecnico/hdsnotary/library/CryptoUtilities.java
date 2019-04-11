package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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

public class CryptoUtilities {
	
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String DIGEST_ALGORITHM = "SHA-256";
	
	private SecureRandom secRandom = new SecureRandom();
	
	private final PrivateKey privateKey;
	private final String userId;
	private final String keysPath;
	private final String password;
	
	public CryptoUtilities(String id, String keysPath, String password) throws KeyStoreException {
		this.userId = id;
		this.keysPath = keysPath;
		this.password = password;
		this.privateKey = getStoredKey(id, keysPath, password);
	}
	
	public boolean verifySignature(String id, String toVerify, byte[] signature) {
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

	public byte[] signMessage(String msg) {
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
	
	public PrivateKey getStoredKey(String id, String keysPath, String password) throws KeyStoreException {
		// Load KeyStore
		KeyStore ks = KeyStore.getInstance("pkcs12");
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
		FileInputStream fis = null;
		PrivateKey priKey = null;
		try {
			fis = new FileInputStream(new File(keysPath));
			ks.load(fis, password.toCharArray());

			// Load PrivateKey
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(id, protParam);
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
	public X509Certificate getStoredCert(String NotaryId) throws KeyStoreException {
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
	
	public String generateCNounce() {
		return new BigInteger(256, secRandom).toString();
	}
}
