package pt.ulisboa.tecnico.hdsnotary.library;

import java.io.Serializable;
import java.util.Objects;

public class BroadcastMessage implements Serializable {

	private final String goodId;
	private final String writerId;
	private final String newOwner;
	private final Boolean forSale;
	private final int timeStamp;

	public BroadcastMessage(String goodId, Boolean forSale, String writerId, String newOwner, int timeStamp) {
		this.goodId = goodId;
		this.forSale = forSale;
		this.writerId = writerId;
		this.timeStamp = timeStamp;
		this.newOwner = newOwner;
	}

	public String getGoodId() {
		return goodId;
	}

	public String getWriterId() {
		return writerId;
	}

	public String getNewOwner() {
		return newOwner;
	}

	public Boolean getForSale() {
		return forSale;
	}

	public int getTimeStamp() {
		return timeStamp;
	}

	@Override
	public int hashCode() {
		return Objects.hash(goodId, writerId, newOwner, forSale, timeStamp);
	}
}
