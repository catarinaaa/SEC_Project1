package pt.ulisboa.tecnico.hdsnotary.library;


import java.io.Serializable;

public class Result implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private Boolean result;
	private String cnounce;
	private byte[] signature;
	
	public Result(Boolean result, String cnounce, byte[] signature) {
		super();
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
		
}
