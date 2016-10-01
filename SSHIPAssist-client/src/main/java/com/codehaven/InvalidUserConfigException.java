package com.codehaven;

/**
* Exception class used to indicate an error in the user configuration file located in src/main/resources/userconfig.
* @author Armand Maree
* @since 1.0
*/
public class InvalidUserConfigException extends Exception {
	public InvalidUserConfigException() {
		super();
	}

	public InvalidUserConfigException(String message) {
		super(message);
	}

	public InvalidUserConfigException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidUserConfigException(Throwable cause) {
		super(cause);
	}
}
