package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.File;
import java.io.FileInputStream;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class User extends UnicastRemoteObject implements UserInterface {
	private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	private static final String ALGORITHM = "DSA";
	private static final String NOTARYPUBKEYPATH = "../Server/storage/notaryPublicKey.txt";

	private final String id;
	// List of all goods possessed
	private ArrayList<Good> goods;
	// Instance of remote Notary Object
	private NotaryInterface notary = null;
	private String publicKeyPath;
	private Random random = new Random();

	PrivateKey privateKey;
	PublicKey publicKey;

	public User(String id, NotaryInterface notary) throws IOException, NoSuchAlgorithmException {
		super();
		this.id = id;
		this.notary = notary;
		this.publicKeyPath = "../Server/storage/pubKey-" + id + ".txt";

		System.out.println("Initializing User");

		// Gerar par de chave publica e privada
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keygen.initialize(1024, random);
		KeyPair pair = keygen.generateKeyPair();

		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();

		// Escrever chaves para keys.txt
		writePublicKeyToFile();

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

//		System.out.println("> " + data + result.getResult());

		if (verifySignature(data + result.getResult(), result.getSignature()))
			return result.getResult();
		else {
			System.out.println("Signature does not verify!");
			return false;
		}
	}

//	public void test() throws Exception {
//		byte[] data = "Hey, this was signed".getBytes();
//		Signature dsaForSign = Signature.getInstance("SHA1withDSA");
//		dsaForSign.initSign(privateKey);
//		dsaForSign.update(data);
//		byte[] signature = dsaForSign.sign();
//
//		dsaForSign.initVerify(publicKey);
//		dsaForSign.update(data);
//		System.out.println("> " + dsaForSign.verify(signature));
//
//	}

	public boolean sell(String goodId) {
		try {
			String nounce = notary.getNounce(this.id);
			String cnounce = generateCNounce();
			String str = nounce + cnounce + this.id + goodId;
//			System.out.println(str);
			byte[] dataDigested = hashMessage(str);
			byte[] hashSigned = signByteArray(dataDigested);

			System.out.println("Intention > " + notary.intentionToSell(this.id, goodId, cnounce, hashSigned).getResult());

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
			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
			FileInputStream pubKeyStream = new FileInputStream(NOTARYPUBKEYPATH);
			int pubKeyLength = pubKeyStream.available();
			byte[] pubKeyBytes = new byte[pubKeyLength];
			pubKeyStream.read(pubKeyBytes);
			pubKeyStream.close();
//			System.out.println(">>>> " + bytesToHex(pubKeyBytes));
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
			sig.initVerify(publicKey);

			byte[] hashedMsg = hashMessage(toVerify);
			sig.update(hashedMsg);
			if (sig.verify(signature))
				return true;
			else
				return false;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | SignatureException
				| InvalidKeyException e) {
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
			dsaForSign = Signature.getInstance("SHA1withDSA");
			dsaForSign.initSign(privateKey);
			dsaForSign.update(array);
			return dsaForSign.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	private void writePublicKeyToFile() throws IOException {
		File file = new File(publicKeyPath);
		if (!file.exists()) {
			file.createNewFile();
			System.out.println("Creating new file");
		}
		FileOutputStream output = new FileOutputStream(publicKeyPath);
		output.write(publicKey.getEncoded());
		output.flush();
		output.close();

	}

	public void listGoods() {

	}

}
