# SSHIPAssist

If you ISP uses DHCP to allocate an IP address to you then you might have come across the problem where you want to connect to your home PC but the external IP address changed since the last time you checked. This leaves you locked out until you get home.

SSHIPAssist keeps the external IP address of a machine syncronized with an external server. This allows you to retrieve that IP address remotely and use it to SSH in to the machine. This can obviously also be used for other IP related tasks other than SSH.

## Implementation Details

SSHIPAssist is written in Java and used Gradle as the build tool. You do not need to install Gradle since the Gradle wrapper script is provided. A few dependencies will be downloaded when you run the program for the first time.

## Requirements

* Linux machine.

## Setup

* Clone the repository onto your local computer.
* Open the file located at src/main/resources/userconfig.
* Supply all the required details (See section "User Configuration" for more information).

## Execute

Bash scripts are included for simplified execution on Linux machines. Other OSs can still use the program but will have to look at the client.bash and server.bash files to see how it needs to be executed.

* To execute the server (see section "Server" for more information) execute ./server.bash
* To execute the client (see section "Client" for more information) execute ./client.bash
* Add the --help argument to get a list of command that can be used with either of these programs.

## User Configuration

The file that contains all the user details is located at src/main/resources/userconfig. The fields that can be used is:

* username - will be used to register/login to [Code Haven](http://codehaven.co.za). Field is required.
* password - will be used to register/login to [Code Haven](http://codehaven.co.za). Field is required. (See section "Encryption and Hashing" for more information)
* devname - device name associated with the IP address that has to be stored or retrieved. Field is required.
* key - the 16 character code that will be used to encrypt the IP before it is sent to the server. This means Code Haven can never see the IP addresses that you save unless you provide the key that was used to encrypt the IP. (See section "Encryption and Hashing" for more information)
* once - if the value is true then the IP address will only be sent to the server once and then the program executes. This field only applies to the server program and is optional.
* updateinterval - the time in milliseconds between each update. If no interval is specified then it defaults to 10 minutes. This field only applies to the server program and is optional.

## Server

The server is the part of SSHIPAssist that will run on the device that needs to send it's IP address. By default the program will run continuously and send the external IP every 10 minues. That means that if your ISP changes your external IP address in between two updates, then you have to wait for the next update.

## Client

The client is the part of SSHIPAssist that will run of the machine that needs to know the IP of another machine. It will only run once and display the IP address to the screen.

## Encryption and Hashing

### SSHIPAssist IP Encryption

AES is used to encrypt IP addresses in the server application before it is sent to [Code Haven](http://codehaven.co.za) to be saved. A 128 bit (16 character) key is used to encrypt the IP address. The key you use to encrypt should remain a secret in order to protect you. This is should also be used to decrypt the IP address on the client.

It is recommended to change the key on your server and client frequently for the same reason you should change your passwords on any website frequently.

You can either choose your own 16 character key or you can use the --genkey argument on the server that generates a random key. This is the recommended way to go.

## Code Haven Password Hashing

Code haven does not store any passwords. We use the SHA-512 hashing algorithm with a 1000 iterations to validate your identity when you login.
