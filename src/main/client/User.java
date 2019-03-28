package main.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.Mac;

import main.notary.Good;
import main.notary.NotaryInterface;

public class User implements UserInterface {
	private final String id;
	private ArrayList<Good> goods;
	NotaryInterface notary = null;
	private String path = "keys.txt";
	private Random random = new Random();
	
	PrivateKey privateKey;
	PublicKey publicKey;
	
	public User(String id) throws NoSuchAlgorithmException {
		super();
		this.id = id;
		this.path = "pubKey-"+id+".txt";
		
		System.out.println("Initializing Client");
		
		//Gerar par de chave publica e privada
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keygen.initialize(1024, random);
		KeyPair pair = keygen.generateKeyPair();
		
		privateKey = pair.getPrivate();
		publicKey = pair.getPublic();
		
		//Escrever chaves para keys.txt
		try {
			File file = new File(path);
			if(!file.exists()) {
				file.createNewFile();
				System.out.println("Creating new file");
			}
			// changed true -> false
			//BufferedWriter output = new BufferedWriter(new FileWriter(file, false));
			FileOutputStream output = new FileOutputStream(path);
			//output.write(id + " " + publicKey);
			output.write(publicKey.getEncoded());
			output.flush();
			output.close();
			
			FileOutputStream keyfos = new FileOutputStream("suepk");
			keyfos.write(publicKey.getEncoded());
			keyfos.close();
			
			
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		
		
		try {
			notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");
		}
		catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.out.println("Error locating Notary");
			e.printStackTrace();
			return;
		}
		// inicializar vetor
	}

	public String getId() {
		return id;
	}

	public ArrayList<Good> getGoods() {
		return goods;
	}

	@Override
	public Boolean buyGood(String userId, String goodId) throws RemoteException {
		
		return notary.transferGood(this.getId(), userId, goodId);
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
	
	
	public boolean sell() {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			String nounce = notary.getNounce(this.id);
			String cnounce = generateCNounce();
			String str = nounce + cnounce + this.id + "good2";
			System.out.println(str);
			byte[] dataDigested = digest.digest(str.getBytes("UTF-8"));
			
			Signature dsaForSign = Signature.getInstance("SHA1withDSA");
			dsaForSign.initSign(privateKey);
			dsaForSign.update(dataDigested);
			byte[] hashSigned = dsaForSign.sign();
			
			System.out.println(notary.intentionToSell(this.id, "good2", cnounce, dataDigested, hashSigned));
			
		} catch (NoSuchAlgorithmException | RemoteException | UnsupportedEncodingException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	private String generateCNounce() {
		return new BigInteger(256, random).toString();
	}
	
	private static String bytesToHex(byte[] hash) {
	    StringBuffer hexString = new StringBuffer();
	    for (int i = 0; i < hash.length; i++) {
	    String hex = Integer.toHexString(0xff & hash[i]);
	    if(hex.length() == 1) hexString.append('0');
	        hexString.append(hex);
	    }
	    return hexString.toString();
	}
	
}
