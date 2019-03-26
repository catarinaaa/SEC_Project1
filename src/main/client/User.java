package main.client;

import java.util.ArrayList;

import main.notary.Good;

public class User implements UserInterface {
	private final String id;
	private ArrayList<Good> goods;
	
	public User(String id) {
		super();
		this.id = id;
		
		// inicializar vetor
	}

	public String getId() {
		return id;
	}

	public ArrayList<Good> getGoods() {
		return goods;
	}

	
}
