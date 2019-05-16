package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;
import java.util.Objects;

public class BroadcastMessage implements Serializable {

	private final String goodId;
	private final String writerId;
	private final String newOwner;
	private final Boolean forSale;
	private final int timeStamp;

	public BroadcastMessage(String goodId, Boolean forSale, String writerId, String newOwner,
		int timeStamp) {
		this.goodId = goodId;
		this.forSale = forSale;
		this.writerId = writerId;
		this.timeStamp = timeStamp;
		this.newOwner = newOwner;
	}

	public String getGoodId() {
		return goodId;
	}

	@Override
	public int hashCode() {
		return Objects.hash(goodId, writerId, newOwner, forSale, timeStamp);
	}

	@Override
	public boolean equals(Object o) {
		BroadcastMessage other = (BroadcastMessage) o;
		return other.goodId.equals(this.goodId) && other.forSale.equals(this.forSale)
			&& other.timeStamp == this.timeStamp && other.newOwner.equals(this.newOwner);
	}

	@Override
	public String toString() {
		return "BroadcastMessage{" +
			"goodId='" + goodId + '\'' +
			", writerId='" + writerId + '\'' +
			", newOwner='" + newOwner + '\'' +
			", forSale=" + forSale +
			", timeStamp=" + timeStamp +
			'}';
	}
}
