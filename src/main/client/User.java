package main.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;

import main.notary.Good;
import main.notary.NotaryInterface;

public class User implements UserInterface {
	private final String id;
	private ArrayList<Good> goods;
	NotaryInterface notary = null;
	private String path = "keys.txt";
	
	public User(String id) throws NoSuchAlgorithmException {
		super();
		this.id = id;
		
		System.out.println("Initializing Client");
		
		//Gerar par de chave publica e privada
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keygen.initialize(1024, random);
		KeyPair pair = keygen.generateKeyPair();
		
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();
		
		//Escrever chaves para keys.txt
		try {
			File file = new File(path);
			if(!file.exists()) {
				file.createNewFile();
				System.out.println("Creating new file");
			}
			BufferedWriter output = new BufferedWriter(new FileWriter(file, true));
			output.write(id + " " + publicKey);
			output.flush();
			output.close();
			
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

	
}
