# Secure Chat System

This is a fully functional secure chat system that offers a command line interface that allows multiple users to talk to multiple other users simultaneously through a chat server.

Full trust is placed in this chat hub as it addresses all network security aspects including : managing conversation sessions, negotiating cipher suites, securely exchanging keys between users using Elliptic-curve Diffie–Hellman (ECDH) key exchange algorithm, verifying digital signatures and certificates, keeping track of all authenticated users, encrypting / decrypting messages using symmetric cipher algorithm AES with GCM integrity protection mode. It prevents and detects any security attacks throughout the chat session.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

```
git clone git@github.com:sunnymeow/SecureChatSystem.git
```

### Prerequisites

Our development environment :

* git version 2.7.4 (Apple Git-66)

* java version "1.8.0_73"

* Java(TM) SE Runtime Environment (build 1.8.0_73-b02)

* Java HotSpot(TM) 64-Bit Server VM (build 25.73-b02, mixed mode)

As long as you have git and JDK installed, you are fine.

### Installing

A step by step series of examples that tell you have to get a development env running

Open one terminal, and navigate into the project folder.

```
cd [PATH/TO/SecureChatSystem]
```

Make sure all files needed are there, including all java. And .jks files.

```
ls
```

Enter “make” in the command line. This command will compile all java files necessary to run the chat hub.

```
make
```

In the SAME terminal, type “make server”, this will create a server socket and start the dispatcher thread to infinitely accept client connections.

```
make server
```

Open a 2nd terminal, type “make alice” to allow the server connect and authorize the first client whose alias must be "alice". 

```
make alice
```

Open a 3rd terminal, type “make bob” to allow the server connect and authorize the second client whose alias must be "bob".

```
make bob
```

Open a 4th terminal, type “make charles” to allow the server connect and authorize the fourth client with alias "charles". 

```
make charles
```

Open a 5th terminal, type “make david” to allow the server connect and authorize the second client whose alias must be "david".

```
make david
```

Now, any one of the four clients can send messages to any other client or ALL clients including himself / herself.

To send messages to one other client, enter "To alias:message" in the corresponding terminal window.

```
To [ALIAS]:message
```

To send messages to all active clients, enter "To all:message". This command will also forward a copy of the message to the sender himself / herself.

```
To all:message
```

Any one in the chathub can stop the conversation by enter “exit”. But the other conversations will not terminated until all clients exit.

```
exit
```

All logs will be printed out in the server terminal window in real time, including runtime environment, cipher suite negotiation details, ECHD key exchange processes, signature and certiifcate verification and more.

## Disclaimer

* NakovChatServer class is entry point for the program, it must be the very 1st program to run.

* During the conversation, sender MUST follow “To alias:message” or “To all:message” format. Failure of doing this will result in message sending failure. For example,  “To bob: Hi, how are you” or “To all: hi, I am Alice” is okay, but “Hi, bob” or “Hi everyone” is wrong.

* This program only deals with four clients. In fact, this program can add as many as client when needed. To add a client, a keystore and a self-signed certificate are needed to be established for the new client. Once the client keystore switches certificates with the chathub keystore, this client is ready to be added into the chat hub.

## What's In The Makefile

```
make
```
compiles all java programs.

```
make server
```
executes server.

```
make alice
``` 
executes client with a Java keystore alice.jks that was already built.

```
make bob
``` 
executes client with keystore bob.jks.

```
make charles
```
executes client class with keystore charles.jks.

```
make david
```
executes client class that with keystore david.jks.

```
make clean
```
removes all the .class files.

## What Each Class Does

**NakovChatServer.java**

---

This is entry point for the program because it opens a serversocket. It infinitely accepts client socket connections, and add accepted clients into the client list stored in ServerDispatcher class.

**ClientInfo.java**

---

A simple class that helps server to hold information about a client.

**ServerDispatcher**

---

This class has a message queue and a hash map structure that stores client information. The message queue manages all messages sent from the clients and dispatches them to desired client socket. The hash map keeps track of all connected, hence registered and authenticated clients.

**ClientSender.java**

---

This class handles sending messages from server socket to the client socket. Outgoing messages are popped from ServerDispatcher’s message queue, then they are stored in ClientSender’s message queue. In the case that ClientSender’s message queue is empty,  ClientSender will wait for the new message to arrive. Once ClientSender’s message queue receives message, it encrypts the messages with server’s shared secret key and sends the ciphertext to the client socket.

**ClientListener.java**

---

This class receives client messages from client socket, decrypts the messages with server’s shared secret key, and add them to the message queue in ServerDispatcher class.

**NakovChatClient.java**

---

This class creates client socket that connects to the server socket. It also reads messages sent from the server socket, decrypts the ciphertexts with client’s shared secret key, and displays the plaintexts on standard output.

**Sender.java**

---

Sender class reads messages from keyboard input, encrypts them into ciphertext with client’s shared secret key, and sends them to the server socket.

**Help.java**

---

This class is a collection of various helper functions that are used by both client and server. For example, method "commandEqual" is used to checks whether a byte array and a string are "equal" through Base64 encoding / decoding. Another example might be that method "findCipherSuite" handles negotiation of cipher suites.

**KeyExchange.java**

---

This class contains methods that implement ECDH key exchange algorithm to generate key pairs and construct the shared secret key.

**Encryption.java**

---

This class uses symmetric cipher algorithm AES, with either CBC or GCM mode, to encrypt and decrypt messages. Shared secret key used by AES algorithm comes from ECDH key exchange.

**ErrorException.java**

---

This class handles all exceptions that were thrown.

## Authors

* **(c) Svetlin Nakov, 2002** - *Initial work* - [Nakov Chat Server](http://www.nakov.com)

See also the list of [contributors](https://github.com/sunnymeow/SecureChatSystem/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* This multithread client/server chat design is based on Internet Programming with [Java Course](http://inetjava.sourceforge.net/lectures/part1_sockets/InetJava-1.9-Chat-Client-Server-Example.html)
