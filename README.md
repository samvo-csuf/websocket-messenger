# websocket-messenger

# 

# Author: Samuel Vo
# CPSC 455-02
# Credit: Usage of AI(ChatGPT, Claude) were used for assistance
# Also used some FastAPI websockets documentation for reference
# https://fastapi.tiangolo.com/advanced/websockets/#await-for-messages-and-send-messages
# https://fastapi.tiangolo.com/advanced/templates/#using-jinja2templates

# Instructions to run SecureChat

1. First clone the repo

2. Setup a local PostgreSQL Database and edit the .env file with your database configurations
- Create a database and name it anything you want. Remember to include the username, password, and the default port is 5432.

3. Set up a virtual environment by running "python -m venv venv" command.
  - To activate it run "venv/Scripts/Activate" in the terminal before you run the program.

4. Run a command "pip install -r requirements.txt" to install all of the dependencies.

5. You must also generate a certificate and key file using openssl command and store it in the secure_chat folder to be used with the program. 
- Run this openssl command "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"

6. Once everything is configured and set up then activate the virtual environment then run command "python run.py"

7. The run.py should be able to start the server and run the program. 



# NOTES
# Was able to get two devices to communicate over the same network, but the only issue was that it required disabling Windows Defender Firewall for it to work. 
# I also was not able to figure out and implement the Connection Handling Feature because I was having so much issues. Therefore, I left it out on this iteration. However, I will continue to work on it and try to implement it into my program in the future iteration. 
