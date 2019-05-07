package pt.ulisboa.tecnico.hdsnotary.library;

public class Good {
	private String userId;
	private String goodId;
	private Boolean forSale;
	
	public Good(String userId, String goodId) {
		super();
		this.userId = userId;
		this.goodId = goodId;
		this.forSale = false;
	}
	
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getGoodId() {
		return goodId;
	}
	public void setGoodId(String goodId) {
		this.goodId = goodId;
	}

	public Boolean forSale() {
		return forSale;
	}

	public void setForSale() {
		this.forSale = true;
	}
	
	public void notForSale() {
		this.forSale = false;
	}
}
