# websocket-messenger
#DOCUMENTATION
 
 Author: Samuel Vo
 CPSC 455-02
 Credit: Usage of AI(ChatGPT, Claude) were used for assistance and better understanding of topics

# System Requirements
- Latest version of Python
- PostgreSQL (pgAdmin is GUI version and what I used for db configuration)
- 

- Link to the Video:
 

# NEW Version of SecureChat (Python Program)
# Old Version was FastAPI application (Got too complex)
# Instructions to run SecureChat

1. First clone the repo

2. Setup a local PostgreSQL Database and edit the .env.example back to .env file with your database configurations
- Create a database and name it anything you want. Remember to include the username, password, and the default port is 5432.

3. Create a new file to generate the Encryption key

4. Run a command "pip install -r requirements.txt" to install all of the dependencies.


(SKIP THIS STEP, I HAD ISSUES TRYING TO MAKE IT WSS CONNECTION FOR THIS VERSION, WILL BE FIXED IN NEXT ITERATION)
5. You must also generate a certificate and key file using openssl command and store it in the secure_chat folder to be used with the program. 
- Run this openssl command "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
- Recommend to keep the names "key.pem" and "cert.pem" to be consistent with the program setup. 

6. Once everything is configured and set up then open a terminal and run command "python run.py"
- Open another terminal to run the client. Use command: "python -m http.server 8000". The last number is the port used. 
- Next, go into a browser and type the localhost address "127.0.0.1:8000" It should redirect you to the sign-in page.
- Create a new account in sign up, it should redirect to the sign-in, then after that it should enter the chat.

7. The server.py should be able to start the server and the python -m http.server 8000 command should serve the client on a browser. 



# IMPORTANT ISSUES UNRESOLVED
- I wasn't able to implement wss secure connection handling for this iteration.
- I got some minor bugs which shows the user joined when logged in, and Disconnect when creating an account. 
- When a user leaves it doesn't show the status they left. 
- Was able to get heartbeat functionality partially working. When the server reconnects, I have to refresh manually. 
- Had difficulties with encryption for file sharing, so it sends, but data gets corrupted when sent to recipient.
- Did not have time for implementing Security hardening features like brute force detection. 
- All changelog commit history is in the github url at the top and add /commits at the end to see the history
- I also don't have my program in .exe or deployed on a web browser for this iteration due to time constraints. 
- I plan to deploy it on the web in a future iteration. 
- I don't know how my personal account got into collaboration when I was signed in my school account the whole time, but I worked on the project solo. There was no anonymous contributor or anything, just my 2 accounts. 