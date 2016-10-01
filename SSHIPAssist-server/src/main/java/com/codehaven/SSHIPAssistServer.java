package com.codehaven;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;

/**
* Main class that handles all communication and functionality.
* @author Armand Maree
* @since 1.0
*/
public class SSHIPAssistServer {
	private final String USER_AGENT = "Mozilla/5.0";
	private boolean executeOnlyOnce = false;

	/**
	* Prints the basic usage in the command line to the screen.
	*/
	public static void usage() {
		System.out.println("Usage: ./server [options]");
		System.out.println("Options:");
		System.out.println("\t--genkey\t\tGenerate a key that can be placed in the src/main/resources/userconfig file.");
		System.out.println("\t--register\t\tRegister as a user on http://codehaven.co.za with the details in src/main/resources/userconfig.");
		System.out.println("\t\t\t\tThis must be done to use this service. SHA-512 (1000 iterations) hashing is used to secure passwords.");
		System.out.println("\t--once\t\tOnly post IP once and then stop the program.");
		System.out.println("\t-v,--version\t\tDisplay the version of this program.");
		System.out.println("\t-h,--help\t\tDisplay this menu.");
	}

	/**
	* Prints the version of this program to the screen.
	*/
	public static void version() {
		System.out.println("SSHIPAssistServer Server version 1.0");
	}

	/**
	* Generates a 128 bit (16 characters) random string.
	* @return A key that can be used as the AES encrypt/decrypt key.
	*/
	public static String generateSecKey() {
		return new BigInteger(130, new SecureRandom()).toString(32).substring(0, 16);
	}

	/**
	* Main method that controls the flow of the program.
	* @param args The command line arguments.
	*/
	public static void main(String[] args) {
		SSHIPAssistServer sshipassist = new SSHIPAssistServer();

		for (String arg : args) {
			// Parse argumants
			switch (arg) {
				case "--genkey" :
					System.out.println("AES encryption key: " + generateSecKey());
					return;
				case "--register" :
					try {
						System.out.println("Reading config...");
						Map<String, String> details = sshipassist.readConfig();

						if (!sshipassist.register(details))
							return;
					}
					catch (Exception e) {
						e.printStackTrace();
						System.exit(1);
					}
					break;
				case "--once" :
					sshipassist.setExecuteOnlyOnce(true);
					break;
				case "-h":
				case "--help" :
					usage();
					return;
				case "-v":
				case "--version" :
					version();
					return;
				default:
					System.out.println("Unknown option: " + arg);
					usage();
					return;
			}
		}

		try {
			while (true) {
				System.out.println();
				System.out.println("Reading config...");
				Map<String, String> details = sshipassist.readConfig();

				if (details.get("username") == null)
					throw new InvalidUserConfigException("No username specified in userconfig file.");
				if (details.get("password") == null)
					throw new InvalidUserConfigException("No password specified in userconfig file.");
				if (details.get("devname") == null)
					throw new InvalidUserConfigException("No devname specified in userconfig file.");
				if (details.get("key") == null)
					throw new InvalidUserConfigException("No key specified in userconfig file. Use the -generatekey flag to get a key.");
				if (details.get("once") != null)
					sshipassist.setExecuteOnlyOnce(details.get("once").equals("true"));
				if (details.get("updateinterval") == null) {
					System.out.println("Using default update interval of 10 minutes.");
					int updateinterval = 10 * 60 * 1000;
					details.put("updateinterval", updateinterval + "");
				}

				System.out.println("Encrypting IP address...");
				details.put("ip", sshipassist.encrypt(sshipassist.getIp(), details.get("key")));
				System.out.println("Sending request for " + details.get("devname") + " with IP (encrypted) " + details.get("ip") + ".");
				String response = sshipassist.sendIp(details);
				System.out.println("Server response:\n" + response);

				if (sshipassist.getExecuteOnlyOnce() || response.startsWith("ERROR"))
					break;

				Thread.sleep(Integer.parseInt(details.get("updateinterval")));
			}
		}
		catch (Exception e) { // catch all exceptions
			e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	* Registers a user based on the provided details.
	* @param All the details of a user required to register them to codehave.co.za.
	* @param details Hashmap of the details of the user. Must contain username and password.
	* @return True for success and false for failure.
	*/
	public boolean register(Map<String, String> details) throws Exception {
		if (details.get("username") == null || details.get("password") == null)
			throw new InvalidUserConfigException("No username of password specified in userconfig file.");

		String url = "http://codehaven.co.za/sshipassist/register/";

		HttpClient client = HttpClientBuilder.create().build();
		HttpPost post = new HttpPost(url);

		// add header
		post.setHeader("User-Agent", USER_AGENT);

		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		urlParameters.add(new BasicNameValuePair("username", details.get("username")));
		urlParameters.add(new BasicNameValuePair("password", details.get("password")));

		post.setEntity(new UrlEncodedFormEntity(urlParameters));

		HttpResponse response = client.execute(post);
		System.out.println("HTTP Response Code: " + response.getStatusLine().getStatusCode());

		BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		StringBuffer result = new StringBuffer();
		String line;

		while ((line = rd.readLine()) != null)
			result.append(line);

		String resultString = result.toString();

		if (resultString.startsWith("200")) {
			System.out.println(resultString.substring(4));
			return true;
		}
		else {
			System.out.println("ERROR " + resultString.substring(0, 3) + ": " + resultString.substring(4));
			return false;
		}
	}

	/**
	* Set the value of executeOnlyOnce.
	* @param executeOnlyOnce Specify wither the IP should only be sent once.
	*/
	public void setExecuteOnlyOnce(boolean executeOnlyOnce) {
		this.executeOnlyOnce = executeOnlyOnce;
	}

	/**
	* Returns the value of executeOnlyOnce.
	* @return Specify wither the IP should only be sent once.
	*/
	public boolean getExecuteOnlyOnce() {
		return this.executeOnlyOnce;
	}

	/**
	* Reads the user configuration file.
	* <p>
	*	The user configuration file is located at src/main/resources/userconfig. This file contains the details necessary to use the service. The supported fields in this file is:
	* 	<ul>
	*		<li>username - username as it will be used on codehaven.co.za(required)</li>
	*		<li>password - password as it will be used on codehaven.co.za(required)</li>
	*		<li>devname - device name that the IP must be registered to.(required)</li>
	*		<li>key - The AES encryption/decryption key. (required)</li>
	*		<li>once - if true then the IP address will only be sent once then the program will stop. (optional)</li>
	*		<li>updateinterval - The time in milliseconds between sending requests. (optional)</li>
	* 	</ul>
	* </p>
	* @return A hashmap of the details in the userconfig file.
	*/
	public Map<String, String> readConfig() throws IOException, InvalidUserConfigException {
		InputStream in = SSHIPAssistServer.class.getResourceAsStream("/userconfig");
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		Map<String, String> details = new HashMap<>();
		String line;
		int lineCounter = 1;

		while ((line = reader.readLine()) != null) {
			String[] keyvalue = line.split("=");

			if (keyvalue.length != 2)
				throw new InvalidUserConfigException("Line " + lineCounter + " does not contain a key value pair seperated by an equals sign (=).");

			details.put(keyvalue[0], keyvalue[1]);
			lineCounter++;
		}

		reader.close();

		return details;
	}

	/**
	* Get the external IP of this network from Amazon AWS.
	* @return String representation of the external IP of this network.
	*/
	public String getIp() throws Exception {
		URL whatismyip = new URL("http://checkip.amazonaws.com");
		BufferedReader in = new BufferedReader(new InputStreamReader(whatismyip.openStream()));
		String ip = in.readLine();
		return ip;
	}

	/**
	* Encrypts a given piece plain text with the provided key.
	* <p>
	*	This method will encrypt plain text with AES, a key length of 128 bits and then convert it into a hexadecimal representation.
	* </p>
	* @param plainText The text that needs to be encrypted.
	* @param key The 128 bit key that the text must be encrypted with.
	* @return The encrypted text.
	*/
	public String encrypt(String plainText, String key) throws Exception {
		if (key.length() != 16)
			throw new InvalidKeyException("Key must be 16 characters long. Use the -generatekey flag to get a key.");

		SecretKey secKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
		return bytesToHex(byteCipherText);
	}

	/**
	* Convert a byte array into a string of hexadecimal.
	* @param hash The byte array that needs to be converted.
	* @return The hexadecimal string representation of the array.
	*/
	public String bytesToHex(byte[] hash) {
		return DatatypeConverter.printHexBinary(hash);
	}

	/**
	* Sends the IP address to be stored on codehaven.
	* <p>
	*	Uses HTTP Post to connect to http://codehaven.co.za/sshipassist/setip/ and stores the IP of a given device name. The username and password combination has to be registered to codehaven.co.za.
	* </p>
	* @param details A hashmap of details about the user. Must contain a username, password, devname (device name) and ip.
	* @return The message received from the server. If an error occurred the text will start with "ERROR".
	*/
	public String sendIp(Map<String, String> details) throws Exception {
		String url = "http://codehaven.co.za/sshipassist/setip/";

		HttpClient client = HttpClientBuilder.create().build();
		HttpPost post = new HttpPost(url);

		// add header
		post.setHeader("User-Agent", USER_AGENT);

		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		urlParameters.add(new BasicNameValuePair("username", details.get("username")));
		urlParameters.add(new BasicNameValuePair("password", details.get("password")));
		urlParameters.add(new BasicNameValuePair("devname", details.get("devname")));
		urlParameters.add(new BasicNameValuePair("ip", details.get("ip")));

		post.setEntity(new UrlEncodedFormEntity(urlParameters));

		HttpResponse response = client.execute(post);
		System.out.println("HTTP Response Code: " + response.getStatusLine().getStatusCode());

		BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		StringBuffer result = new StringBuffer();
		String line;

		while ((line = rd.readLine()) != null)
			result.append(line);

		String resultString = result.toString();

		if (resultString.startsWith("200"))
			resultString = resultString.substring(4);
		else
			resultString = "ERROR " + resultString.substring(0, 3) + ": " + resultString.substring(4);

		return resultString;
	}
}
