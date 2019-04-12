package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;

public class Transfer implements Serializable {
	
	private final int id;
	private final String buyerId;
	private final String sellerId;
	private final String goodId;
	private final byte[] notarySignature;
	
	public Transfer(int id, String buyerId, String sellerId, String goodId, byte[] notarySignature) {
		super();
		this.id = id;
		this.buyerId = buyerId;
		this.sellerId = sellerId;
		this.goodId = goodId;
		this.notarySignature = notarySignature;
	}

	public String getBuyerId() {
		return buyerId;
	}

	public String getSellerId() {
		return sellerId;
	}

	public String getGoodId() {
		return goodId;
	}

	public byte[] getNotarySignature() {
		return notarySignature;
	}	

	public int getId() {
		return this.id;
	}
}
