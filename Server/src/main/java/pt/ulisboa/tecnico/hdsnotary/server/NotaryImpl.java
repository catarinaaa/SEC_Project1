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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;
import java.util.TreeMap;
import pt.ulisboa.tecnico.hdsnotary.library.*;


public class NotaryImpl extends UnicastRemoteObject implements NotaryInterface, Serializable {

	private static final String ALGORITHM = "SHA1withRSA";
	private static final long serialVersionUID = 1L;
	private final static String PATH = "Server/storage/database.txt";

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
				System.out.println("Creating new file " + PATH);
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
			

		} catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
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
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");

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
			System.err.println("ERROR: writing to file failed");
			System.exit(1);
		}
	}

	private void populateList() {

		goodsList.put("good1", new Good("Alice", "good1"));
		goodsList.put("good2", new Good("Alice", "good2"));
		goodsList.put("good3", new Good("Alice", "good3"));
		goodsList.put("good4", new Good("Bob", "good4"));
		goodsList.put("good5", new Good("Charlie", "good5"));
		goodsList.put("good6", new Good("Charlie", "good6"));

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
			System.err.println("ERROR: Closing files failed");
			System.exit(1);
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
//			String pubKeyPath = "Server/pubKey-" + userId + ".txt";
//			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
//			FileInputStream pubKeyStream = new FileInputStream(pubKeyPath);
//			int pubKeyLength = pubKeyStream.available();
//			byte[] pubKeyBytes = new byte[pubKeyLength];
//			pubKeyStream.read(pubKeyBytes);
//			pubKeyStream.close();
//			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
//			
			
			PublicKey publicKey = getStoredKey(userId);//keyFactory.generatePublic(pubKeySpec);

			Signature sig = Signature.getInstance(ALGORITHM);
			sig.initVerify(publicKey);

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(dataStr.getBytes("UTF-8"));
			sig.update(hashed);
			if (sig.verify(signature)) {
				System.out.println("Hashs are the same and have not been modified");
				return true;
			} else {
				System.err.println("ERROR: signature verification failed");
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
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return false;
	}

	private PublicKey getStoredKey(String userId) throws KeyStoreException {
		//Load KeyStore
	    KeyStore ks = KeyStore.getInstance("pkcs12");
	    FileInputStream fis = null;
	    PublicKey publicKey = null;
	    try {
	        fis = new FileInputStream(new File("Client/storage/" + userId + ".p12"));
	        ks.load(fis, (userId + "1234").toCharArray());
	        
		    //Load PublicKey
		    Certificate cert = ks.getCertificate(userId);
		    publicKey = cert.getPublicKey();
		      
	        if (fis != null) {
	            fis.close();
	        } 
	    } catch (FileNotFoundException | CertificateException e) {
	    	System.err.println("ERROR: KeyStore/certificate of user" + userId + " not found");
	    	System.exit(1);
	    } catch(IOException e) {
	    	System.err.println("ERROR: Wrong password of KeyStore");
	    	System.exit(1);
	    } catch(NoSuchAlgorithmException e) {
	    	System.err.println("ERROR: Wrong algorithm in KeyStore");
	    	System.exit(1);	    	
	    }
	    return publicKey;
	}
	
	
	private void writePublicKeyToFile() throws IOException {
		File file = new File("Server/storage/notaryPublicKey.txt");
		if (!file.exists()) {
			file.createNewFile();
			System.out.println("Creating new file Server/notaryPublicKey.txt");
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
			System.err.println("ERROR: Signing message failed");
			System.exit(1);
		}
		return null;
	}


}
