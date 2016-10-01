package com.codehaven;

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
