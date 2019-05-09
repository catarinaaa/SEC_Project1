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
    private final int readID;
    private final byte[] writeSignature;
    private final String writerId;

    public Result(String userId, Object content, int writeTimestamp, int readID, String writerId, byte[] writeSignature, byte[] signature) {
        super();
        this.userId = userId;
        this.content = content;
        this.signature = signature;
        this.writeTimestamp = writeTimestamp;
        this.readID = readID;
        this.writerId = writerId;
        this.writeSignature = writeSignature;
    }

    public Result(String userId, Object content, int writeTimestamp, byte[] signature) {
        super();
        this.userId = userId;
        this.content = content;
        this.signature = signature;
        this.writeTimestamp = writeTimestamp;
        this.readID = -1;
        this.writeSignature = null;
        this.writerId = null;
    }

    public Result(Object content, int writeTimestamp, byte[] signature) {
        super();
        this.userId = null;
        this.content = content;
        this.signature = signature;
        this.writeTimestamp = writeTimestamp;
        this.readID = -1;
        this.writeSignature = null;
        this.writerId = null;
    }

    public Result(Object content, byte[] signature) {
        // TODO delete
        super();
        this.userId = null;
        this.content = content;
        this.signature = signature;
        this.writeTimestamp = -1;
        this.readID = -1;
        this.writeSignature = null;
        this.writerId = null;
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

    public int getReadID() {
        return readID;
    }

    public String getWriterId() {
        return writerId;
    }

    public byte[] getWriteSignature() {
        return writeSignature;
    }

    @Override
    public boolean equals(Object o) {
        Result r = (Result) o;
//		System.out.println(userId + " " +content + " " +r.getUserId() + " " +r.getContent());
        if (userId == null || content == null || r.getUserId() == null || r.getContent() == null) {
            return false;
        }
        return (userId.equals(r.getUserId()) && content.equals(r.getContent())
                && writeTimestamp == r.writeTimestamp);
    }
}
