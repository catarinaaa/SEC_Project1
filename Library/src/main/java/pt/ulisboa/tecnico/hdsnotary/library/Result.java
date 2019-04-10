package pt.ulisboa.tecnico.hdsnotary.library;


import java.io.Serializable;

public class Result implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private String userId;
	private Boolean result;
	private Transfer transfer;
	private String cnounce;
	private byte[] signature;
	
	public Result(Boolean result, String cnounce, byte[] signature) {
		super();
		this.userId = null;
		this.result = result;
		this.cnounce = cnounce;
		this.signature = signature;
		this.transfer = null;
	}
	
	public Result(Boolean result, Transfer transfer, String cnounce, byte[] signature) {
		super();
		this.userId = null;
		this.result = result;
		this.cnounce = cnounce;
		this.signature = signature;
		this.transfer = transfer;
	}

	public Result(String userId, Boolean result, String cnounce, byte[] signature) {
		super();
		this.userId = userId;
		this.result = result;
		this.cnounce = cnounce;
		this.signature = signature;
	}
	
	public Boolean getResult() {
		return result;
	}
	
	public byte[] getSignature() {
		return signature;
	}
	
	public String getUserId() {
		return userId;
	}

	public Transfer getTransfer() {
		return transfer;
	}

	public String getCnounce() {
		return cnounce;
	}
}
