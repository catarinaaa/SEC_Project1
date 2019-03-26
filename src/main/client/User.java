package main.client;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.ArrayList;

import main.notary.Good;
import main.notary.NotaryInterface;

public class User implements UserInterface {
	private final String id;
	private ArrayList<Good> goods;
	NotaryInterface notary = null;
	
	public User(String id) {
		super();
		this.id = id;
		
		System.out.println("Initializing Client");
		
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
