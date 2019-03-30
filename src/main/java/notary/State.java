package main.java.notary;

import java.io.Serializable;

public class State implements Serializable {

	private final String userId;
	private final boolean state;
	
	public String getUserId() {
		return userId;
	}
	public boolean getState() {
		return state;
	}
	public State(String userId, boolean state) {
		super();
		this.userId = userId;
		this.state = state;
	}
		
}
