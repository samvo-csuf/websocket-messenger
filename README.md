# websocket-messenger
#DOCUMENTATION
 
 Author: Samuel Vo
 CPSC 455-02
 Credit: Usage of AI(ChatGPT, Claude) were used for assistance and better understanding of topics
 Also used some FastAPI websockets documentation for reference:
 - https://fastapi.tiangolo.com/advanced/websockets/#await-for-messages-and-send-messages
 - https://fastapi.tiangolo.com/advanced/templates/#using-jinja2templates

 - Link to the Video:
 - https://drive.google.com/file/d/19Ca17taCitzLAOoOeGkmYQRTxQnUdE5t/view?usp=sharing

# Instructions to run SecureChat

1. First clone the repo

2. Setup a local PostgreSQL Database and edit the .env.example back to .env file with your database configurations
- Create a database and name it anything you want. Remember to include the username, password, and the default port is 5432.

3. Set up a virtual environment by running "python -m venv venv" command.
  - To activate it run "venv/Scripts/Activate" in the terminal before you run the program.

4. Run a command "pip install -r requirements.txt" to install all of the dependencies.

5. You must also generate a certificate and key file using openssl command and store it in the secure_chat folder to be used with the program. 
- Run this openssl command "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
- Recommend to keep the names "key.pem" and "cert.pem" to be consistent with the program setup. 

6. Once everything is configured and set up then activate the virtual environment then run command "python run.py"

7. The run.py should be able to start the server and run the program. 



# IMPORTANT NOTES
- Was able to get two devices to communicate over the same network, but the only issue was that it required disabling Windows Defender Firewall for it to work. 
 - I also was not able to figure out and implement the Connection Handling Feature because I was having so much issues. Therefore, I left it out on this iteration. However, I will continue to work on it and try to implement it into my program in the future iteration. 
 - All changelog commit history is in the github url at the top and add /commits at the end to see the history
 - I don't know how my personal account got into collaboration when I was signed in my school account the whole time, but I worked on the project solo. There was no anonymous contributor or anything, just my 2 accounts. 