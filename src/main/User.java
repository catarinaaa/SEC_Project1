package main;

import java.util.ArrayList;

public class User {
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
