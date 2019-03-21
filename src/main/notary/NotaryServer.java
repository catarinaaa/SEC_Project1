package main.notary;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class NotaryServer {

	public static void main(String[] args) {
		int port = 3000;
		System.out.println("Main OK");

		SecurityManager sm = System.getSecurityManager();

		try {
			NotaryImpl obj = new NotaryImpl();

			Registry reg = LocateRegistry.createRegistry(port);
			reg.rebind("Notary", obj);

			System.out.println("Server ready!");

			System.out.println("Awaiting connections");
			System.out.println("Press enter to shutdown");
			System.in.read();
			System.out.println("Server termindated");
			System.exit(0);

		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

	}

}
