time: JCATime.java
	javac JCATime.java
	java JCATime

explore: ExploreJCA.java
	javac ExploreJCA.java
	java ExploreJCA

server: 
	java server

client:
	java client 

chat: 
	javac Conversation.java
	javac server.java
	javac client.java

clean:
	$(RM) *.class
