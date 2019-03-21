package main.notary;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class NotaryImpl extends UnicastRemoteObject implements NotaryInterface, Serializable {
	
	private int counter = 1;
	
	protected NotaryImpl() throws RemoteException {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public boolean intentionToSell(String userId, String goodId) throws RemoteException {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean stateOfGood(String goodId) throws RemoteException {
		// TODO Auto-generated method stub
		return false;
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
		
	
}
