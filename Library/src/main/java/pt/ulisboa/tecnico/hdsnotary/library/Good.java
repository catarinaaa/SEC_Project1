package pt.ulisboa.tecnico.hdsnotary.library;

public class Good {
	private String userId;
	private String goodId;
	
	public Good(String userId, String goodId) {
		super();
		this.userId = userId;
		this.goodId = goodId;
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
}
