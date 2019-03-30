package main.java.notary;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import javax.crypto.Mac;

public class NotaryImpl extends UnicastRemoteObject implements NotaryInterface, Serializable {
	
	private static NotaryImpl instance = null;
	
	private Random random = new Random();
	
	private int counter = 1;
	
	private TreeMap<String, Good> goodsList = new TreeMap<>();
	
	private ArrayList<String> goodsToSell = new ArrayList<String>();
	
	private TreeMap<String, String> nounceList = new TreeMap<>();
	
	private String path = "database.txt";
	private File file = null;
	private BufferedReader input = null;
	private BufferedWriter output = null;
	
	private PrivateKey privateKey = null;
	
	protected NotaryImpl() throws RemoteException {
		super();
		populateList();
		
		
		try {
			file = new File(path);
			if(!file.exists()) {
				file.createNewFile();
				System.out.println("Creating new file");
			}
			input = new BufferedReader(new FileReader(file));
			output = new BufferedWriter(new FileWriter(file, true));
			recoverTransactions();
			printGoods();
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void recoverTransactions() throws IOException {
		System.out.println("Recovering transactions");
		String line;
		String[] splitLine;
		Good good;
		while((line = input.readLine()) != null) {
			splitLine = line.split(";");
			System.out.println("Seller: " + splitLine[0] + " Buyer: " + splitLine[1] + " Good: " + splitLine[2]);
			good = goodsList.get(splitLine[2]);
			good.setUserId(splitLine[1]);
			goodsList.put(splitLine[2], good);
		}
		
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public boolean intentionToSell(String userId, String goodId, String cnounce, byte[] signature) throws RemoteException {
	
		try {
						
			String toHash = nounceList.get(userId) + cnounce + userId + goodId;
			System.out.println(toHash);
			if(!verifySignatureAndHash(toHash, signature, "pubKey-"+userId+".txt"))
				return false;
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		Good good;
		
		if((good = goodsList.get(goodId)) != null) {
			if(good.getUserId().equals(userId) && !goodsToSell.contains(good.getGoodId())) {
				goodsToSell.add(good.getGoodId());
				return true;
			}
		}
		return false;
	}

	

	@Override
	public State stateOfGood(String goodId) throws RemoteException {
		Good good;
		if((good = goodsList.get(goodId)) != null)
			return new State(good.getUserId(), goodsToSell.contains(goodId) ? true : false);
		else
			return null;
	}

	@Override
	public boolean transferGood(String sellerId, String buyerId, String goodId, String cnounce, byte[] signature) throws RemoteException {
		
		String toHash = nounceList.get(sellerId)+cnounce+sellerId+buyerId+goodId;
		if(!verifySignatureAndHash(toHash, signature, "pubKey-"+sellerId+".txt"))
			return false;
		
		
		Good good;
		if((good = goodsList.get(goodId)) != null) {
			if(good.getUserId().equals(sellerId) && goodsToSell.contains(goodId)) {
				good.setUserId(buyerId);
				goodsList.put(goodId, good);
				goodsToSell.remove(goodId);
				saveTransfer(sellerId,buyerId,goodId);
				printGoods();
				return true;
			}
		}
		printGoods();
		return false;
	}

	private void saveTransfer(String sellerId, String buyerId, String goodId) {
		try {
			output.write(sellerId+";"+buyerId+";"+goodId+"\n");
			output.flush();
		} catch (IOException e) {
			System.out.println("Error writing to file");
			e.printStackTrace();
		}		
	}

	@Override
	public String sayHello() throws RemoteException {
		System.out.println("Hey!");
		return "Hello " + counter++ ;
	}
	
	private void populateList() {
		
		goodsList.put("good1", new Good("user1", "good1"));
		goodsList.put("good2", new Good("user1", "good2"));
		goodsList.put("good3", new Good("user1", "good3"));
		goodsList.put("good4", new Good("user2", "good4"));
		goodsList.put("good5", new Good("user3", "good5"));
		goodsList.put("good6", new Good("user3", "good6"));
		
	}
	
	public static NotaryImpl getInstance() {
		if(instance == null) {
			try {
				instance = new NotaryImpl();
			} catch (RemoteException e) {
				e.printStackTrace();
				System.exit(1);
			}
		}
		return instance;
	}
	
	public void printGoods() {
		for (String id : goodsList.keySet()) {
			System.out.println(goodsList.get(id).getUserId() + " - " + id);
		}
	}

	@Override
	public String getNounce(String userId) throws RemoteException {
		BigInteger nounce = new BigInteger(256, random);
		nounceList.put(userId, nounce.toString());
		return nounce.toString();
	}
	
//	public void stop() {
//		try {
//			input.close();
//			output.close();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
//	}
	
	private static String bytesToHex(byte[] hash) {
	    StringBuffer hexString = new StringBuffer();
	    for (int i = 0; i < hash.length; i++) {
	    String hex = Integer.toHexString(0xff & hash[i]);
	    if(hex.length() == 1) hexString.append('0');
	        hexString.append(hex);
	    }
	    return hexString.toString();
	}
	
	private boolean verifySignatureAndHash(String dataStr, byte[] signature, String pubKeyPath)  {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			FileInputStream pubKeyStream = new FileInputStream(pubKeyPath); 
			int pubKeyLength = pubKeyStream.available();
			byte[] pubKeyBytes = new byte[pubKeyLength];
			pubKeyStream.read(pubKeyBytes);
			pubKeyStream.close();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
			
			Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initVerify(publicKey);
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(dataStr.getBytes("UTF-8"));
			sig.update(hashed);
			if(sig.verify(signature)) {
				System.out.println("Hashs are the same and have not been modified");
				return true;
			}
			else {
				System.out.println("ERROR!");
				return false;
			}
		} catch(NoSuchAlgorithmException e) {
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
	
}
