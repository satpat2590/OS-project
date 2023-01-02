# This is the main page for my entire Operating Systems Projects

I completed this project as a course requirement for my CSE 303 (Operating Systems & Design) course, in which we created 
a social media imitation application using only C++ libraries. 

Our overall goal was to create both working parts of a client and server, in which a client is able to register their profile,
name, and profile description. This would then be stored within the database hosted on the server's end. 

There are currently 5 important themes that all Operating Systems must encompass: 

1. Security 
2. Concurrency
3. Persistence
4. Resource Management
5. Virtualization


## Security 

Imagine you're at home and your parents want to send you a post they found to be interesting on Facebook. You don't have a Facebook 
account, so you go on the website/application and decide to create one. 

Off the bat, they'll ask you for your personal information (name, email, phone number, password, etc...). This information, once entered,
will be a part of your unique identity created on Facebook's servers. 

In other words, once you enter a valid username and password, the server will take that information and create a profile for you,
one which can be accessed subsequently using only the username and password provided on account creation. 

You don't need to enter all of your profile information in subsequent times, but only the username and password that you created. 

The reason why is because it is completely secure within the Facebook database. However, how exactly does your sign in information 
validate security to begin with?

### Consider assymetric encryption: 

We use the example of Alice and Bob sending information to one another. In this case, we want to designate Alice to be the client
and Bob to be the server. Bob (our server) starts by generating a pair of RSA keys (both public and private). 

Alice then, using our same example to register our user on an application such as Facebook, will encrypt her 
initial registration data (user, pass, etc...) using the AES encryption method. 

In C/C++, we use the OpenSSL library to encrypt messages. Next, after creating the @ablock (AES encrypted block containing user data),
we then create an @rblock (RSA encrypted data) which contains the custom API commands (REG, GET, SET, ALL), the AES public key, and
the size of the @ablock. 

Once both @ablock and @rblock are packed into the same data structure, namely, a std::vector<uint8> (emulating byte streams), we then 
send it over to the server's end for Bob to decrypt the @rblock and then use the encrypted AES key to decrypt the @ablock. 
  
Another helpful "verification" method is to make sure the size of the @ablock stored within the @rblock is the same. 
If not, then you know there is something wrong with the communication protocol. 
  
Once Bob is able to decrypt the message and verify that the registration is valid (no duplicate user names, valid password, ...)
then Bob is able to send a response to Alice's request. Bob's response is encrypted using base AES and then sent to Alice. 
  
Note, we only consider Alice's information being sent to Bob as important. In a Facebook sense, would it really matter if someone were to
intercept the response, as it only contains whether or not the request was successful or not. 
  
The only part that would warrant security measures is if the interception happened when Alice sent her personal user data to Bob. 
The person intercepting the message would find Alice's username, password, phone number much more important than the simple "OK" or "NO" response. 
  

  
## Concurrency 
  
We learned how important it is to consider security within communication in applications. For Facebook, you want your username and password to 
be secure, because if it isn't, then anyone could simply find your personal user data and imitate you by signing in as you. 
  
Facebook might be a simple example, so let's think about your Bank Account. Assume you just created an account for Bank of America 
and wanted to view your personal bank statements and other private monetary information. To access this information, you simply enter your
username and password and then you have access. Without security, do you get why it would be chaotic to simply send vital user information 
without a system such as assymetric encryption? 
  
Now, let's look further at other elements of major applications such as Facebook and Bank of America. As of right now, we only viewed Alice and Bob as 
an example for this method of communication. Now imagine if Alice loves the app Facebook and wants all of her friends to join so that they can all
stay in touch with each other and see their posts. Currently, Bob is only really able to handle one request at a time, since he is but one person! 
  
For major applications like Facebook, simply having one Bob handle all users is a bit overkill. Load times would be ridiculous, and depending
on how you schedule incoming requests, some users may not even get their chance at using the application until all others in the queue
are handled. 
  
If you are Alice's friend, and you are asked to wait 30 minutes for all other users to send in their requests, then you would simply not 
use the application. You're better off calling each of your friends individually and getting updates about their personal lives. 
  
Consider if there was a way to handle tons and tons of requests in around the same time as each other. 
  
Introducing, C/C++ threads. 
  
Using threads, we can create different processes of the same program, as many as you need! There is still an issue here. If we are talking about
Bob still, then creating different "fork()"s, or different processes of Bob would be hard to manage once you pass a certain limit. 

Bob is still human! He's not able to clone himself 1 million times! Not unless Bob is a super powerful set of servers built for such a strong app!
  
Regardless, in order to handle 10 of Alice's friends, Bob can replicate his process 10 different times, to handle all of the requests. 
We designate a "Main Bob" who is a the leader thread, and is receiving each request. "Main Bob" then sends each request to his "Worker Bobs", 
which are his various replicated processes. 

"Worker Bobs" essentially handle each request (REQ, GET, SET, ALL) and then send back their corresponding responses. Now it isn't just "Main Bob"
who is handling all of the work! This reduces the time it takes to send back the response (let's label this as 'latency'), which in turn
provides joy to all of Alice's friends, who are able to chat with each other and edit their profile in real-time. 
  
Thanks "Worker Bobs"! 
  

  
## Persistence
  


  
