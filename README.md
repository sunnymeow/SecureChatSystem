# Secure Chat System

This is a fully functional secure chat system that allows multiple users to talk to multiple other users simultaneously through a chat hub.

Full trust is placed in this chat hub as it addresses all network security aspects including : managing conversation sessions, negotiating cipher suites, securely exchanging keys between users using Elliptic-curve Diffie–Hellman (ECDH) key exchange algorithm, verifying digital signatures and certificates, keep track of all authenticated users, encrypting / decrypting messages using symmetric cipher algorithm AES with GCM integrity protection mode. It prevents and detects any security attacks throughout the chat session.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

```
git clone git@github.com:sunnymeow/SecureChatSystem.git
```

### Prerequisites

Our development environment :

git version 2.7.4 (Apple Git-66), java version "1.8.0_73", Java(TM) SE Runtime Environment (build 1.8.0_73-b02), Java HotSpot(TM) 64-Bit Server VM (build 25.73-b02, mixed mode)

As long as you have git and JDK installed, you are fine.

### Installing

A step by step series of examples that tell you have to get a development env running

Open one terminal, and navigate into the project folder.

```
cd [PATH/TO/SecureChatSystem]
```

Mmake sure all files needed are there, including all java. And .jks files.

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

* NakovChatServer.java

This is entry point for the program because it opens a serversocket. It infinitely accepts client socket connections, and add accepted clients into ServerDispatcher client list.

* ClientInfo.java

Help server to hold information about a client.

* ServerDispatcher

Has a message queue and a ClientInfo hash map. The message queue manages all messages sent from clients and dispatches them to desired clients socket. The ClientInfo hash map keeps track of all connected clients.

* ClientSender.java

Proposed to send messages from server socket to the client socket. Outgoing messages are popped from ServerDispatcher’s message queue, then they are stored in ClientSender’s message queue. When ClientSender’s message queue is empty, wait for the new message to arrive. Once ClientSender’s message queue receives message, encrypts the messatewith server’s shared secret key and sends the ciphertext to the client socket.

* ClientListener.java

Receives client messages from client socket, decrypts it with server’s shared secret key, and add them to the message queue in ServerDispatcher.

* NakovChatClient.java

Creates client socket that connects to server socket. Reads messages sent from server socket, decrypts the ciphertexts with client’s shared secret key, and displays the plaintexts on standard output.

* Sender.java

Reads messages from the keyboard input, encrypts them into ciphertext with client’s shared secret key, and sends them to the server socket.

* Help.java

Contains various helper functions to make conversation more reliable and convenient. It can be used by both client and server. For example, method commandEqual is purposed to check for matching byte[] and string. Method findCipherSuit is dedigned to look for serverCipher within receivedCipher. If serverCipher not found, throw ErrorException.

* KeyExchange.java

Contains methods using ECDH to generate key pairs and construct the shared secret key.

* Encryption.java

Used either AES/CBC or AES/GCM mode cipher to encrypt and decrypt messages.

* ErrorException.java

used to catch errors.


## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors

* **(c) Svetlin Nakov, 2002** - *Initial work* - [Nakov Chat Server](http://www.nakov.com)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* This multithread client/server chat design is based on Internet Programming with [Java Course](http://inetjava.sourceforge.net/lectures/part1_sockets/InetJava-1.9-Chat-Client-Server-Example.html)
