package pt.ulisboa.tecnico.hdsnotary.library;


import java.io.Serializable;

public class Result implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private final Object content;
	private final String userId;
	private final byte[] signature;
	private final int writeTimestamp;

	public Result(String userId, Object content, int writeTimestamp, byte[] signature) {
		super();
		this.userId = userId;
		this.content = content;
		this.signature = signature;
		this.writeTimestamp = writeTimestamp;
	}
	
	public Result(Object content, int writeTimestamp, byte[] signature) {
		super();
		this.userId = null;
		this.content = content;
		this.signature = signature;
		this.writeTimestamp = writeTimestamp;
	}

	public Result(Object content, byte[] signature) {
		// TODO delete
		super();
		this.userId = null;
		this.content = content;
		this.signature = signature;
		this.writeTimestamp = 0;
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

	public int getWriteTimestamp() {
		return writeTimestamp;
	}

	@Override
	public boolean equals(Object o) {
		Result r = (Result) o;
//		System.out.println(userId + " " +content + " " +r.getUserId() + " " +r.getContent());
		if(userId == null || content == null || r.getUserId() == null || r.getContent() == null)
			return false;
        return (userId.equals(r.getUserId()) && content.equals(r.getContent()) && writeTimestamp == r.writeTimestamp);
	}
}
