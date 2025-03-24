# websocket-messenger
#DOCUMENTATION
 
 Author: Samuel Vo
 CPSC 455-02
 Credit: Usage of AI(ChatGPT, Claude) were used for assistance and better understanding of topics

# System Requirements
- Latest version of Python
- PostgreSQL (pgAdmin is GUI version and what I used for db setup.)

- Link to the Video:
https://drive.google.com/file/d/1W8sSSBKjMjgpJ8n1MoUgM9iWIXuei3ct/view?usp=sharing

Github link:
https://github.com/samvo-csuf/websocket-messenger

(If zip folder doesn't work on Canvas, the github is available)
 

NEW Version of SecureChat (Python Program)
Old Version was FastAPI application (Got too complex)
Instructions to run SecureChat

TESTED on 3 Different browsers

1. First clone the repo

2. Setup a local PostgreSQL Database and edit the .env.example back to .env file with your database configurations
- Create a database and name it anything you want. Remember to include the username, password, and the default port is 5432.
- (IMPORTANT FOR db creation) I used this command to create the table for users, and it includes the hashed and encrypted credentials.
SQL command used for db:
CREATE TABLE users (
    id SERIAL PRIMARY KEY,                
    username_encrypted BYTEA NOT NULL,    
    password_hash VARCHAR(60) NOT NULL,   
    username_hash VARCHAR(64) UNIQUE     
);

3. Create a new file to generate the Encryption key
(You could delete the file after)

- Import at the top of a new file created "generate_key.py"
from cryptography.fernet import Fernet

- Generate a Fernet key
key = Fernet.generate_key()

- Print the key
print("Your Fernet encryption key:")
print(key.decode())

Run "python generate_key.py"

Save the key in the environment variables file. 

4. Run a command "pip install -r requirements.txt" to install all of the dependencies.


(SKIP THIS STEP, I HAD ISSUES TRYING TO MAKE IT WSS CONNECTION FOR THIS VERSION, WILL BE FIXED IN NEXT ITERATION)
5. You must also generate a certificate and key file using openssl command and store it in the secure_chat folder to be used with the program. 
- Run this openssl command "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
- Recommend to keep the names "key.pem" and "cert.pem" to be consistent with the program setup. 

6. Once everything is configured and set up then open a terminal and run command "python server.py"
- Open another terminal to run the client. Use command: "python -m http.server 8000". The last number is the port used. 
- Next, go into a browser and type the localhost address "127.0.0.1:8000" It should redirect you to the sign-in page.
- Create a new account in sign up, it should redirect to the sign-in, then after that it should enter the chat.
- Repeat this for multiple users on different browsers. 

7. The server.py should be able to start the server and the python -m http.server 8000 command should serve the client on a browser. 

- Any issues with port, try changing it to another port. 
- CHANGELOG is located in github link with /commits. 

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