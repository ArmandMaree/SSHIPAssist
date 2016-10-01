package com.codehaven;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringEscapeUtils;

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
public class SSHIPAssistClient {
	private final String USER_AGENT = "Mozilla/5.0";

	/**
	* Prints the basic usage in the command line to the screen.
	*/
	public static void usage() {
		System.out.println("Usage: ./client [options]");
		System.out.println("Options:");
		System.out.println("\t-v,--version\t\tDisplay the version of this program.");
		System.out.println("\t-h,--help\t\tDisplay this menu.");
	}

	/**
	* Prints the version of this program to the screen.
	*/
	public static void version() {
		System.out.println("SSHIPAssistClient version 1.0");
	}

	/**
	* Main method that controls the flow of the program.
	* @param args The command line arguments.
	*/
	public static void main(String[] args) {
		// Parse argumants
		for (String arg : args) {
			switch (arg) {
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

		SSHIPAssistClient sshipassist = new SSHIPAssistClient();

		try {
			System.out.println("Reading config...");
			Map<String, String> details = sshipassist.readConfig();

			if (details.get("username") == null)
				throw new InvalidUserConfigException("No username specified in userconfig file.");
			if (details.get("password") == null)
				throw new InvalidUserConfigException("No password specified in userconfig file.");
			if (details.get("devname") == null)
				throw new InvalidUserConfigException("No devname specified in userconfig file.");
			if (details.get("key") == null)
				throw new InvalidKeyException("No key specified in userconfig file. Use the same key as the one used on the server.");

			System.out.println("Retrieving IP address...");
			System.out.println("Last recorded IP of " + details.get("devname") + " is: " + sshipassist.retrieveIp(details));
		}
		catch (Exception e) { // catch all exceptions
			e.printStackTrace();
			System.exit(1);
		}
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
	* 	</ul>
	* </p>
	* @return A hashmap of the details in the userconfig file.
	*/
	public Map<String, String> readConfig() throws IOException, InvalidUserConfigException {
		InputStream in = SSHIPAssistClient.class.getResourceAsStream("/userconfig");
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
	* Decrypts a given piece of cyper text.
	* <p>
	*	This method will decrypt cypher text that was encrypted with AES, a key length of 128 bits and then converted into a hexadecimal representation.
	* </p>
	* @param cypherText The text that needs to be decrypted.
	* @param key The 128 bit key that the text was encrypted with.
	* @return The decrypted text.
	*/
	public String decrypt(String cypherText, String key) throws Exception {
		if (key.length() != 16)
			throw new InvalidKeyException("Key must be 16 characters long. Use the same key as the one used on the server.");

		byte[] byteCypherText = hexToByte(cypherText);
		SecretKey secKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCypherText);
		return new String(bytePlainText);
	}

	/**
	* Converts a string containing hexadecimal to a byte array.
	* @param hash The hexadecimal string that needs to be converted.
	* @return The byte array represented by the hexadecimal string.
	*/
	public byte[] hexToByte(String hash) {
		int len = hash.length();
	    byte[] data = new byte[len / 2];

	    for (int i = 0; i < len; i += 2)
	        data[i / 2] = (byte) ((Character.digit(hash.charAt(i), 16) << 4) + Character.digit(hash.charAt(i+1), 16));

	    return data;
	}

	/**
	* Retrieves the IP address stored on codehaven.
	* <p>
	*	Uses HTTP Post to connect to http://codehaven.co.za/sshipassist/getip/ and request the IP of a given device and user.
	* </p>
	* @param details A hashmap of details about the user. Must contain a username, password and devname (device name).
	* @return If successful the IP address will be returned, else an error message.
	*/
	public String retrieveIp(Map<String, String> details) throws Exception {
		String url = "http://codehaven.co.za/sshipassist/getip/";

		HttpClient client = HttpClientBuilder.create().build();
		HttpPost post = new HttpPost(url);

		// add header
		post.setHeader("User-Agent", USER_AGENT);

		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		urlParameters.add(new BasicNameValuePair("username", details.get("username")));
		urlParameters.add(new BasicNameValuePair("password", details.get("password")));
		urlParameters.add(new BasicNameValuePair("devname", details.get("devname")));

		post.setEntity(new UrlEncodedFormEntity(urlParameters));

		HttpResponse response = client.execute(post);
		System.out.println("HTTP Response Code: " + response.getStatusLine().getStatusCode());

		BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		StringBuffer result = new StringBuffer();
		String line;

		while ((line = rd.readLine()) != null) {
			if (line.substring(0, 3).equals("200"))
				result.append("200 " + decrypt(line.substring(4), details.get("key")));
			else
				result.append(line);
		}

		String resultString = result.toString();

		if (resultString.startsWith("200"))
			resultString = resultString.substring(4);
		else
			resultString = "ERROR " + resultString.substring(0, 3) + ": " + resultString.substring(4);

		return resultString;
	}
}
