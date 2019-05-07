package pt.ulisboa.tecnico.hdsnotary.library;


import java.io.Serializable;

public class Result implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private Object content;
	private String userId;
	private Boolean result;
	private Transfer transfer;
	private String cnonce;
	private byte[] signature;
	private Good good;

	public Result(Boolean result, String cnonce, byte[] signature) {
		super();
		this.userId = null;
		this.result = result;
		this.cnonce = cnonce;
		this.signature = signature;
		this.transfer = null;
	}
	
	public Result(Boolean result, Transfer transfer, String cnonce, byte[] signature) {
		super();
		this.userId = null;
		this.result = result;
		this.cnonce = cnonce;
		this.signature = signature;
		this.transfer = transfer;
	}

	public Result(String userId, Boolean result, String cnonce, byte[] signature) {
		super();
		this.userId = userId;
		this.result = result;
		this.cnonce = cnonce;
		this.signature = signature;
	}
	
	public Result(String userId, Boolean result, Object content, String cnonce, byte[] signature) {
		super();
		this.userId = userId;
		this.result = result;
		this.content = content;
		this.cnonce = cnonce;
		this.signature = signature;
	}
	
	public Object getContent() {
		return content;
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

	public String getCnonce() {
		return cnonce;
	}

	public Good getGood() { return good; }
}
