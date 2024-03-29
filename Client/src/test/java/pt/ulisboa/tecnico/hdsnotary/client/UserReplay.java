package pt.ulisboa.tecnico.hdsnotary.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.Map;

import pt.ulisboa.tecnico.hdsnotary.library.*;

public class UserReplay extends UnicastRemoteObject implements UserInterface {
	
	private static final long serialVersionUID = 1L;

	private static final String NOTARY_ID = "Notary";
	private static final String NOTARY_CC = "CertCC";

	private final String id;
	private final String user2;
	private final String user3;
	private UserInterface remoteUser2 = null;
	private UserInterface remoteUser3 = null;
	// List of all goods possessed
	private Map<String, Boolean> goods;
	// Instance of remote Notary Object
	private NotaryInterface notary = null;

	
	private String keysPath; // KeyStore location
	private String password; // KeyStore password
	
	CryptoUtilities cryptoUtils;
	
	private Map<String, String> nonceList = new HashMap<>();

	public UserReplay(String id, NotaryInterface notary, String user2, String user3) throws RemoteException, KeyStoreException {

		this.id = id;
		this.notary = notary;
		this.user2 = user2;
		this.user3 = user3;

		goods = new HashMap<String, Boolean>();
		
		this.keysPath = "Client/storage/" + id + ".p12";
		this.password = id + "1234";

		goods = new HashMap<String, Boolean>();

		cryptoUtils = new CryptoUtilities(this.id, this.keysPath, this.password);
		
		System.out.println("Initializing user " + id);

	}

	public String getUser2() {
		return user2;
	}

	public String getUser3() {
		return user3;
	}

	public String getId() {
		return id;
	}

	public Map<String, Boolean> getGoods() {
		return goods;
	}
	
	public void addGood(String goodId, boolean bool) {
		goods.put(goodId, bool);
	}

	@Override
	public String getNonce(String userId, byte[] signature) {
		
		String nounce = cryptoUtils.generateCNonce();
		nonceList.put(userId, nounce);
		return nounce;
	}
	
	public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b));
		   return sb.toString();
		}
	
	@Override
	public Result transferGood(String userId, String goodId, String cnonce, byte[] signature) throws IOException, TransferException {
		try {
			String toVerify = nonceList.get(userId) + cnonce + userId + goodId;

			if (!cryptoUtils.verifySignature(userId, toVerify, signature))
				throw new TransferException("Error");


			String nonceToNotary = cryptoUtils.generateCNonce();
			String data = notary.getNonce(this.id) + nonceToNotary + this.id + userId + goodId;

			byte[] signature2 = cryptoUtils.signMessage(data);

			Transfer result = notary.transferGood(this.getId(), userId, goodId, nonceToNotary, signature2);

			String transferVerify = result.getId() + result.getBuyerId() + result.getSellerId() + result.getGoodId();

			if (cryptoUtils.verifySignature(NOTARY_ID, transferVerify, result.getNotarySignature())) {
				System.out.println("CC Signature verified! Notary confirmed buy good");
				goods.remove(goodId);
				return result;
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				throw new TransferException("Error");
			}
		}
		catch(IOException e) {
			rebind();
			return transferGood(userId, goodId, cnonce, signature);
		}
	}
	
	public boolean buying(String goodId) {
		try {
			Result stateOfGood = stateOfGood(goodId);
			if (stateOfGood == null || false == stateOfGood.getResult()) {
				System.out.println("Good is not up for sale");
				return false;
			}
			else {
				String seller = stateOfGood.getUserId();
				
				if(remoteUser2 == null || remoteUser3 == null) {
					lookUpUsers();
				}
				
				Transfer result;
				
				if(seller.equals(user2) && remoteUser2 != null) {
					
					String nounce = remoteUser2.getNonce(this.id, cryptoUtils.signMessage(this.id));
					String cnounce = cryptoUtils.generateCNonce();
					nonceList.put(user2, cnounce);
					String toSign = nounce + cnounce + this.id + goodId;
					result = remoteUser2.transferGood(this.id, goodId, cnounce, cryptoUtils.signMessage(toSign));
					result = remoteUser2.transferGood(this.id, goodId, cnounce, cryptoUtils.signMessage(toSign));
				}
				else if(seller.equals(user3) && remoteUser3 != null) {
					String nounce = remoteUser3.getNonce(this.id, cryptoUtils.signMessage(this.id));
					String cnounce = cryptoUtils.generateCNonce();
					nonceList.put(user3, cnounce);
					String toSign = nounce + cnounce + this.id + goodId;
					result = remoteUser3.transferGood(this.id, goodId, cnounce, cryptoUtils.signMessage(toSign));
					result = remoteUser3.transferGood(this.id, goodId, cnounce, cryptoUtils.signMessage(toSign));
				}

				goods.put(goodId, false);
				System.out.println("SUCCESSFUL BUY");
				System.out.println(goodId + " was added to the list of goods!");
				System.out.println("------------------");
				return true;

			}
		} catch (IOException e) {
			rebind();
			return buying(goodId);
		}

		catch(TransferException e) {
			System.out.println("Buying not possible!");
			System.out.println("------------------");
			return false;
		}
	}

	public boolean intentionSell(String goodId) {
		try {
			String nounce = notary.getNonce(this.id);
			String cnounce = cryptoUtils.generateCNonce();
			String data = nounce + cnounce + this.id + goodId;
			Result result = notary.intentionToSell(this.id, goodId, cnounce, cryptoUtils.signMessage(data));
			
			if (result != null && cryptoUtils.verifySignature(NOTARY_ID, data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed intention to sell");
				goods.replace(goodId, true);
				System.out.println("Result: " + goodId + " is now for sale");
				return result.getResult();
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				return false;
			}
		} catch (RemoteException e) {
			rebind();
			return intentionSell(goodId);
		}
	}
	
	public Result stateOfGood(String goodId) {
		try {
			String cnounce = cryptoUtils.generateCNonce();
			String data = notary.getNonce(this.id) + cnounce + this.id + goodId;
			
			System.out.println("DATA: " + data);
	
			Result result = notary.stateOfGood(this.getId(), cnounce, goodId, cryptoUtils.signMessage(data));
	
			System.out.println("> " + data + result.getResult());
	
			if (cryptoUtils.verifySignature(NOTARY_CC, data + result.getResult(), result.getSignature())) {
				System.out.println("Signature verified! Notary confirmed state of good message");
				System.out.println("For sale: " + result.getResult() +"\n");
				return result;
			}
			else {
				System.err.println("ERROR: Signature does not verify");
				return result;
			}
		} catch(RemoteException e) {
			rebind();
			return stateOfGood(goodId);
		}
	}
	
	public void rebind() {
		try {
        	Registry reg = LocateRegistry.getRegistry(3000);
			this.notary = (NotaryInterface) Naming.lookup("//localhost:3000/Notary");
            reg.rebind(getId(), this);
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			e.printStackTrace();
		}
	}
	
	public void listGoods() {
		for (String goodId: goods.keySet()){
			Boolean value = goods.get(goodId);
            System.out.println(goodId + " --> For sale: " + value);
		} 
	}
	
	private void lookUpUsers() {
		System.out.println(getUser2());
		System.out.println(getUser3());
		try {
			remoteUser2 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser2());
			remoteUser3 = (UserInterface) Naming.lookup("//localhost:3000/" + getUser3());
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.err.println("ERROR looking up user");
		}
	}
}
