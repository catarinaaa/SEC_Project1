package main.java.notary;

import java.io.Serializable;

public class TransferResult implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Boolean result;
	private byte[] signature;
	public TransferResult(Boolean result, byte[] signature) {
		super();
		this.result = result;
		this.signature = signature;
	}
	public Boolean getResult() {
		return result;
	}
	public byte[] getSignature() {
		return signature;
	}
		
}
