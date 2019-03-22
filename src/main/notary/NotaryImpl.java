package main.notary;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.TreeMap;

public class NotaryImpl extends UnicastRemoteObject implements NotaryInterface, Serializable {
	
	private int counter = 1;
	
	private TreeMap<String, Good> goodsList = new TreeMap<>();
	
	private ArrayList<String> goodsToSell = new ArrayList<String>();
	
	protected NotaryImpl() throws RemoteException {
		super();
		populateList();
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public boolean intentionToSell(String userId, String goodId) throws RemoteException {
		Good good;
		
		if((good = goodsList.get(goodId)) != null) {
			if(good.getUserId().equals(userId) && !goodsToSell.contains(good.getGoodId())) {
				goodsToSell.add(good.getGoodId());
				return true;
			}
		}
		return false;
	}

	@Override
	public State stateOfGood(String goodId) throws RemoteException {
		Good good;
		if((good = goodsList.get(goodId)) != null)
			return new State(goodsList.get(goodId).getUserId(), goodsToSell.contains(goodId) ? true : false);
		else
			return null;
	}

	@Override
	public boolean transferGood(String buyerId, String goodId) throws RemoteException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String sayHello() throws RemoteException {
		System.out.println("Hey!");
		return "Hello " + counter++ ;
	}
	
	private void populateList() {
		
		goodsList.put("good1", new Good("user1", "good1"));
		goodsList.put("good2", new Good("user1", "good2"));
		goodsList.put("good3", new Good("user1", "good3"));
		goodsList.put("good4", new Good("user2", "good4"));
		goodsList.put("good5", new Good("user3", "good5"));
		goodsList.put("good6", new Good("user3", "good6"));
		
	}
		
	
}
