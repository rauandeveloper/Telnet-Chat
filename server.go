package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"id"`
	Nickname string `json:"nickname"`
	Password string `json:"password"`
	Muted    bool   `json:"muted"`
	Banned   bool   `json:"banned"`
}

type Message struct {
	UserID  string    `json:"user_id"`
	Content string    `json:"content"`
	Time    time.Time `json:"time"`
}

type ChatServer struct {
	Users       map[string]User      `json:"users"`
	Messages    []Message            `json:"messages"`
	MutedUsers  map[string]time.Time `json:"muted_users"`
	BannedUsers map[string]time.Time `json:"banned_users"`
	OnlineUsers map[string]string    `json:"online_users"`
	AdminID     string               `json:"admin_id"`
	mu          sync.Mutex
}

var server ChatServer

func loadData() {
	file, err := os.Open("data.json")
	if err != nil {
		if os.IsNotExist(err) {
			server = ChatServer{
				Users:       make(map[string]User),
				Messages:    []Message{},
				MutedUsers:  make(map[string]time.Time),
				BannedUsers: make(map[string]time.Time),
				OnlineUsers: make(map[string]string),
			}
			return
		}
		log.Fatal(err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&server); err != nil {
		log.Fatal(err)
	}
}

func saveData() {
	file, err := os.Create("data.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(server); err != nil {
		log.Fatal(err)
	}
}

func updateTitle() {
	server.mu.Lock()
	defer server.mu.Unlock()

	totalUsers := len(server.Users)
	onlineUsers := len(server.OnlineUsers)
	bannedUsers := 0
	mutedUsers := 0
	lastMessageTime := "No messages yet"

	for _, user := range server.Users {
		if user.Banned {
			bannedUsers++
		}
		if user.Muted {
			mutedUsers++
		}
	}

	if len(server.Messages) > 0 {
		lastMessageTime = server.Messages[len(server.Messages)-1].Time.Format(time.RFC1123)
	}

	title := fmt.Sprintf("Online: %d | Total Users: %d | Banned Users: %d | Muted Users: %d | Last Message: %s", onlineUsers, totalUsers, bannedUsers, mutedUsers, lastMessageTime)
	fmt.Printf("\033]0;%s\007", title)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.Write([]byte("Welcome to the chat! Please log in or register.\n"))

	reader := bufio.NewReader(conn)
	var loggedInUser User

	for {
		updateTitle()
		conn.Write([]byte("> "))
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error reading from client:", err)
			return
		}

		input := strings.TrimSpace(line)
		parts := strings.Split(input, " ")
		cmd := parts[0]

		switch cmd {
		case "/register":
			if len(parts) != 3 {
				conn.Write([]byte("Usage: /register <nickname> <password>\n"))
				continue
			}
			nick, pass := parts[1], parts[2]
			handleRegister(conn, nick, pass)

		case "/login":
			if len(parts) != 3 {
				conn.Write([]byte("Usage: /login <nickname> <password>\n"))
				continue
			}
			nick, pass := parts[1], parts[2]
			loggedInUser = handleLogin(conn, nick, pass)

		case "/msg":
			if loggedInUser.Nickname == "" {
				conn.Write([]byte("You must log in first.\n"))
				continue
			}
			message := strings.Join(parts[1:], " ")
			handleMessage(conn, loggedInUser, message)

		case "/personal":
			if loggedInUser.Nickname == "" {
				conn.Write([]byte("You must log in first.\n"))
				continue
			}
			if len(parts) < 3 {
				conn.Write([]byte("Usage: /personal <nickname> <message>\n"))
				continue
			}
			targetNick := parts[1]
			message := strings.Join(parts[2:], " ")
			handlePersonalMessage(conn, loggedInUser, targetNick, message)

		case "/ban", "/unban", "/mute", "/unmute":
			if loggedInUser.ID != server.AdminID {
				conn.Write([]byte("You do not have permission to use this command.\n"))
				continue
			}
			handleAdminCommand(conn, parts)

		case "/info":
			if len(parts) != 2 {
				conn.Write([]byte("Usage: /info <nickname>\n"))
				continue
			}
			nick := parts[1]
			handleInfo(conn, nick)

		default:
			if loggedInUser.Nickname != "" {
				handleMessage(conn, loggedInUser, input)
			} else {
				conn.Write([]byte("Unknown command or you are not logged in.\n"))
			}
		}
	}
}

func handleRegister(conn net.Conn, nick, pass string) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if _, exists := server.Users[nick]; exists {
		conn.Write([]byte("Nickname already taken.\n"))
		return
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		conn.Write([]byte("Error registering user.\n"))
		return
	}

	id := fmt.Sprintf("%d", len(server.Users)+1)
	server.Users[nick] = User{ID: id, Nickname: nick, Password: string(hashedPass), Muted: false, Banned: false}
	saveData()
	conn.Write([]byte("Registration successful.\n"))
}

func handleLogin(conn net.Conn, nick, pass string) User {
	server.mu.Lock()
	defer server.mu.Unlock()

	user, exists := server.Users[nick]
	if !exists {
		conn.Write([]byte("User not found.\n"))
		return User{}
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))
	if err != nil {
		conn.Write([]byte("Invalid password.\n"))
		return User{}
	}

	if user.Banned {
		conn.Write([]byte("You are banned from this chat.\n"))
		return User{}
	}
	server.OnlineUsers[user.ID] = conn.RemoteAddr().String()
	conn.Write([]byte("Login successful.\n"))
	return user
}

func handleMessage(conn net.Conn, user User, message string) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if user.Muted {
		conn.Write([]byte("You are muted and cannot send messages.\n"))
		return
	}

	server.Messages = append(server.Messages, Message{UserID: user.ID, Content: message, Time: time.Now()})
	saveData()

	for _, addr := range server.OnlineUsers {
		if targetConn, err := net.Dial("tcp", addr); err == nil {
			defer targetConn.Close()
			targetConn.Write([]byte(fmt.Sprintf("%s: %s\n", user.Nickname, message)))
		}
	}
}

func handlePersonalMessage(conn net.Conn, sender User, targetNick, message string) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if sender.Muted {
		conn.Write([]byte("You are muted and cannot send messages.\n"))
		return
	}

	targetUser, exists := server.Users[targetNick]
	if !exists {
		conn.Write([]byte("User not found.\n"))
		return
	}

	if targetAddr, ok := server.OnlineUsers[targetUser.ID]; ok {
		if targetConn, err := net.Dial("tcp", targetAddr); err == nil {
			defer targetConn.Close()
			targetConn.Write([]byte(fmt.Sprintf("Personal message from %s: %s\n", sender.Nickname, message)))
			conn.Write([]byte("Message sent.\n"))
		} else {
			conn.Write([]byte("Error sending message.\n"))
		}
	} else {
		conn.Write([]byte("User is not online.\n"))
	}
}

func handleAdminCommand(conn net.Conn, args []string) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if len(args) < 3 {
		conn.Write([]byte("Usage: /<command> <id> <time> <reason>\n"))
		return
	}

	action := args[0]
	targetID := args[1]
	duration, err := time.ParseDuration(args[2])
	if err != nil {
		conn.Write([]byte("Invalid time format.\n"))
		return
	}
	reason := strings.Join(args[3:], " ")

	var targetUser User
	for _, user := range server.Users {
		if user.ID == targetID {
			targetUser = user
			break
		}
	}

	if targetUser.ID == "" {
		conn.Write([]byte("User not found.\n"))
		return
	}

	switch action {
	case "/ban":
		targetUser.Banned = true
		server.BannedUsers[targetUser.ID] = time.Now().Add(duration)
		conn.Write([]byte(fmt.Sprintf("User %s banned for %s. Reason: %s\n", targetID, duration, reason)))

	case "/unban":
		targetUser.Banned = false
		delete(server.BannedUsers, targetUser.ID)
		conn.Write([]byte(fmt.Sprintf("User %s unbanned.\n", targetID)))

	case "/mute":
		targetUser.Muted = true
		server.MutedUsers[targetUser.ID] = time.Now().Add(duration)
		conn.Write([]byte(fmt.Sprintf("User %s muted for %s. Reason: %s\n", targetID, duration, reason)))

	case "/unmute":
		targetUser.Muted = false
		delete(server.MutedUsers, targetUser.ID)
		conn.Write([]byte(fmt.Sprintf("User %s unmuted.\n", targetID)))

	default:
		conn.Write([]byte("Unknown admin command.\n"))
		return
	}

	server.Users[targetUser.Nickname] = targetUser
	saveData()
}

func handleInfo(conn net.Conn, nick string) {
	server.mu.Lock()
	defer server.mu.Unlock()

	user, exists := server.Users[nick]
	if !exists {
		conn.Write([]byte("User not found.\n"))
		return
	}

	muted := "no"
	if user.Muted {
		muted = "yes"
	}
	banned := "no"
	if user.Banned {
		banned = "yes"
	}

	conn.Write([]byte(fmt.Sprintf("User: %s\nMuted: %s\nBanned: %s\n", user.Nickname, muted, banned)))
}

func main() {
	loadData()
	defer saveData()

	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("Chat server started on :9000")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}
