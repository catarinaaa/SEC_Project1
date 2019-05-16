package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;
import java.util.Objects;

public class Transfer implements Serializable {
	
	private final int id;
	private final String buyerId;
	private final String sellerId;
	private final Good good;
	private final byte[] notarySignature;
	
	public Transfer(int id, String buyerId, String sellerId, Good good, byte[] notarySignature) {
		super();
		this.id = id;
		this.buyerId = buyerId;
		this.sellerId = sellerId;
		this.good = good;
		this.notarySignature = notarySignature;
	}

	public String getBuyerId() {
		return buyerId;
	}

	public String getSellerId() {
		return sellerId;
	}

	public Good getGood() {	return good; }

	public byte[] getNotarySignature() {
		return notarySignature;
	}	

	public int getId() {
		return this.id;
	}
	
	@Override
	public boolean equals(Object o) {
		Transfer r = (Transfer) o;

		if(buyerId == null || sellerId == null || r.getBuyerId() == null || r.getSellerId() == null)
			return false;
        return (buyerId.equals(r.getBuyerId()) && sellerId.equals(r.getSellerId()));
	}
	
    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.buyerId, this.sellerId, this.good);
    }
	
}
