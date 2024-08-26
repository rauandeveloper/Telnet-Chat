Chat Server with User Management in Go

This repository contains a multi-user chat server implemented in Go with Telnet support. It includes features for user authentication, message handling, and administrative commands. The server provides a command-line interface for users to interact with the chat, register, log in, send messages, and perform administrative actions.
Features

    User Authentication: Users can register and log in with a nickname and password.
    Message Handling: Send public messages to all connected users or private messages to specific users.
    Administrative Commands: Admins can ban, unban, mute, or unmute users and view user information.
    User Management: Track online status, muted and banned users.
    User-friendly Interface: A simple text-based interface with clear command usage instructions.
    Title Display: Displays server statistics including the number of online users, total users, banned users, muted users, and the timestamp of the last message.
    Data Storage: User data, messages, and user statuses are stored in a JSON file for persistence.
    Encryption: User passwords are securely hashed using bcrypt.

Commands

    /register <nickname> <password>: Register a new user.
    /login <nickname> <password>: Log in an existing user.
    /msg <message>: Send a public message to all users.
    /personal <nickname> <message>: Send a private message to a specific user.
    /ban <id> <duration> <reason>: Ban a user for a specified duration.
    /unban <id>: Unban a previously banned user.
    /mute <id> <duration> <reason>: Mute a user for a specified duration.
    /unmute <id>: Unmute a previously muted user.
    /info <nickname>: Get information about a user.


Clone the Repository:

    git clone https://github.com/rauandeveloper/Telnet-Chat.git

    cd Telnet-Chat

Build and Run:

    go build -o server
    ./server

Connect via Telnet:

    telnet localhost 9000

Configuration

    Data Storage: Configuration and data are stored in data.json.
    Port: The server listens on port 9000 by default.

Contributing

Feel free to open issues or submit pull requests for improvements or bug fixes. Contributions are welcome!
