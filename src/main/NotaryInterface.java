package main;

public interface NotaryInterface {

	public boolean intentionToSell(String userId, String goodId);
	
	public boolean stateOfGood(String goodId);
	
	public boolean transferGood(String buyerId, String goodId);
}
