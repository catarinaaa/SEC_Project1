package pt.ulisboa.tecnico.hdsnotary.server;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class NotaryServer {

	private static Registry reg;

	public static void main(String[] args) {
		int port = 3000;
		boolean useCC = true;

		if(args.length == 1) {
			useCC = Boolean.parseBoolean(args[0]);
		}

		try {
			NotaryImpl obj = NotaryImpl.getInstance(useCC, "Notary");

			reg = LocateRegistry.createRegistry(port);
			reg.rebind("Notary", obj);

			for (String s : reg.list()) {
				System.out.println("> " + s);
			}
			
			System.out.println("Server ready!");

			System.out.println("Awaiting connections");
			System.out.println("Press enter to shutdown");
			System.in.read();
			obj.stop();
			System.out.println("Server terminated");
			System.exit(0);

		} catch (Exception e) {
			System.err.println("ERROR: Aborting...");
			e.printStackTrace();
			return;
		}

	}

}
