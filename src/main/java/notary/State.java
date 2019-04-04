package main.java.notary;

import java.io.Serializable;

public class State implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final String userId;
	private final boolean state;
	private final String cnounce;
	private final byte[] signature;
	
	
	public String getUserId() {
		return userId;
	}
	
	public boolean getState() {
		return state;
	}
	
	public byte[] getSignature() {
		return signature;
	}
	
	public String getCnounce() {
		return cnounce;
	}
	
	public State(String userId, boolean state, String cnounce, byte[] signature) {
		super();
		this.userId = userId;
		this.state = state;
		this.cnounce = cnounce;
		this.signature = signature;
	}
		
}
