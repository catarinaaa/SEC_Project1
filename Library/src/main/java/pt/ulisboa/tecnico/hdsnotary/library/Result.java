package pt.ulisboa.tecnico.hdsnotary.library;


import java.io.Serializable;

public class Result implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private Object content;
	private String userId;
	private Transfer transfer;
	private String cnonce;
	private byte[] signature;
	private int writeTimestamp;
	private Good good;

	public Result(String userId, Object content, String cnonce, byte[] signature) {
		super();
		this.userId = userId;
		this.content = content;
		this.cnonce = cnonce;
		this.signature = signature;
	}
	
	public Result(Object content, byte[] signature) {
		super();
		this.content = content;
		this.signature = signature;
	}
	
	public Object getContent() {
		return content;
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

	public int getWriteTimestamp() {
		return writeTimestamp;
	}

	public void setWriteTimestamp(int writeTimestamp) {
		this.writeTimestamp = writeTimestamp;
	}
	
	public Good getGood() { return good; }
	
	@Override
	public boolean equals(Object o) {
		Result r = (Result) o;
		System.out.println(userId + " " +content + " " +r.getUserId() + " " +r.getContent());
		if(userId == null || content == null || r.getUserId() == null || r.getContent() == null)
			return false;
        return (userId.equals(r.getUserId()) && content.equals(r.getContent()));
	}
}
