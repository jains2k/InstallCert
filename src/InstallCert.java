import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class InstallCert {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			String ksFileName = "D:/Java/jre1.5.0_14/lib/security/cacerts";
			if (args!= null && args.length > 0 && args[0] != null && !"".equals(args[0].trim())) {
				ksFileName = args[0];
			}
			String serverName = "www.google.com";
			if (args != null && args.length > 1 && args[1] != null && !"".equals(args[1].trim())) {
				serverName = args[1];
			}
			System.out.println("Using keystore file name: " + ksFileName);
			System.out.println("Using server name: " + serverName);
			File file = new File(ksFileName);
			
			SSLContext context = SSLContext.getInstance("TLS");
			InputStream in = new FileInputStream(file);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(in, "changeit".toCharArray());
			in.close();
			
			TrustManagerFactory tmf =
			    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);
			X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
			SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
			context.init(null, new TrustManager[] {tm}, null);
			SSLSocketFactory factory = context.getSocketFactory();

		    // Create the client socket
		    int port = 443;
            if (serverName.contains(":")) {
                String[] strs = serverName.split(":");
                serverName = strs[0];
                port = Integer.parseInt(strs[1]);
            }
//		    String hostname = "hostname";
//		    SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory();
//		    SSLSocket socket = (SSLSocket)factory.createSocket("sdgwssepgqa01.ieptc.intuit.net", port);
		    SSLSocket socket = (SSLSocket)factory.createSocket(serverName, port);
		    // Connect to the server
		    try {
		    	socket.startHandshake();
		    }
		    catch (Exception e) {
		    	//System.out.println(e.getMessage());
		    }

			X509Certificate[] chain = tm.chain;
			if (chain == null) {
			    System.out.println("Could not obtain server certificate chain");
			    return;
			}
			for (int i = 0; i < chain.length; i++) {
			    X509Certificate cert = chain[i];
			    System.out.println
			    	(" " + (i + 1) + " Subject " + cert.getSubjectDN());
			    System.out.println("   Issuer  " + cert.getIssuerDN());
			    addToKeyStore(file, "changeit".toCharArray(), "TT Admin", cert);
			    System.out.println("Added....");
			}
		    // Retrieve the server's certificate chain
//		    java.security.cert.Certificate[] serverCerts =
//		        socket.getSession().getPeerCertificates();
//		    
//		    System.out.println("num certs = " + serverCerts.length);
//		    
//		    for (Certificate cert: serverCerts) {
//		    	System.out.println("cert = " + cert.toString() + "; " + cert.getPublicKey());
//		    }

		    // Close the socket
		    socket.close();
		} catch (SSLPeerUnverifiedException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// This method adds a certificate with the specified alias to the specified keystore file.
	public static void addToKeyStore(File keystoreFile, char[] keystorePassword,
	         String alias, java.security.cert.Certificate cert) {
	    try {
	        // Create an empty keystore object
	        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

	        // Load the keystore contents
	        FileInputStream in = new FileInputStream(keystoreFile);
	        keystore.load(in, keystorePassword);
	        in.close();

	        // Add the certificate
	        keystore.setCertificateEntry(alias, cert);

	        // Save the new keystore contents
	        FileOutputStream out = new FileOutputStream(keystoreFile);
	        keystore.store(out, keystorePassword);
	        out.close();
	    } catch (java.security.cert.CertificateException e) {
	    	e.printStackTrace();
	    } catch (NoSuchAlgorithmException e) {
	    	e.printStackTrace();
	    } catch (FileNotFoundException e) {
	    	e.printStackTrace();
	        // Keystore does not exist
	    } catch (KeyStoreException e) {
	    	e.printStackTrace();
	    } catch (IOException e) {
	    	e.printStackTrace();
	    }
	}

    private static class SavingTrustManager implements X509TrustManager {

    	private final X509TrustManager tm;
    	private X509Certificate[] chain;

    	SavingTrustManager(X509TrustManager tm) {
    	    this.tm = tm;
    	}

    	public X509Certificate[] getAcceptedIssuers() {
    	    throw new UnsupportedOperationException();
    	}

    	public void checkClientTrusted(X509Certificate[] chain, String authType)
    		throws CertificateException {
    	    throw new UnsupportedOperationException();
    	}

    	public void checkServerTrusted(X509Certificate[] chain, String authType)
    		throws CertificateException {
    	    this.chain = chain;
    	    tm.checkServerTrusted(chain, authType);
    	}
    }
}
