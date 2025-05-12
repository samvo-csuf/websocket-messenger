# websocket-messenger
#DOCUMENTATION
 
 Author: Samuel Vo
 CPSC 455-02
 Credit: Usage of AI(ChatGPT, Claude) were used for assistance and better understanding of topics

# System Requirements
- Latest version of Python
- PostgreSQL (pgAdmin is GUI version and what I used for db setup.)

- Link to the Video:
https://drive.google.com/file/d/1UTMOcOlfOexSubkPPF7NGvTjChdk8Cgi/view?usp=sharing

Github link:
https://github.com/samvo-csuf/websocket-messenger

(If zip folder doesn't work on Canvas, the github is available)
 
Instructions to run SecureChat

TESTED on 3 Different browsers

1. First clone the repo

2. Setup a local PostgreSQL Database and edit the .env.example back to .env file with your database configurations
- Create a database and name it anything you want. Remember to include the username, password, and the default port is 5432.
- (IMPORTANT FOR db creation) I used this command to create the table for users, and it includes the hashed and encrypted credentials.
- I used 2 databases this time. One for managing brute force login attempts and the other for user credentials.
SQL command used for db:
  CREATE TABLE IF NOT EXISTS users (
                        username_hash VARCHAR(64) PRIMARY KEY,
                        password_hash TEXT NOT NULL)

I used this SQL command for creating the login_attempts db 
to store attempts of brute-force:
   CREATE TABLE IF NOT EXISTS login_attempts (
                        username_hash VARCHAR(64) PRIMARY KEY,
                        failed_attempts INTEGER DEFAULT 0,
                        last_failed_attempt TIMESTAMP,
                        locked_until TIMESTAMP)

(Store the DB credentials in the environment variables file.)

4. Run a command "pip install -r requirements.txt" to install all of the dependencies.

5. You must also generate a certificate and key file using openssl command and store it in the same folder to be used with the program. 
- Run this openssl command "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
- Recommend to keep the names "key.pem" and "cert.pem" to be consistent with the program setup. 

6. Once everything is configured and set up then open a terminal and run command "python server.py"
- Open another terminal to run the client. Use command: "python https_server.py". 
- Next, go into a browser and paste the localhost address with port 8443 for https.
- Create a new account in sign up, it should redirect to the sign-in, then after that it should enter the chat.
- Repeat this for multiple users on different browsers. 

7. The server.py should be able to start the server and the python https_server.py command should serve the client on a browser. 

- CHANGELOG is located in github link with /commits. 

# IMPORTANT ISSUES UNRESOLVED
- No Link available for online access (Unfortunately)
- When a user leaves it doesn't show the status they left.
- Had difficulties with encryption for sending messages
- All changelog commit history is in the github url at the top and add /commits at the end to see the history
- I don't know how my personal account got into collaboration when I was signed in my school account the whole time, but I worked on the project solo. There was no anonymous contributor or anything, just my 2 accounts. 