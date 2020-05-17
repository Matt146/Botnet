from flask import Flask
from flask import request
import json
import requests

app = Flask(__name__)

PORT = "4600"

class HTTPRequestStruct:
    def __init__(self, method, host, path, headers, body):
        self.method = method
        self.host = host
        self.path = path
        self.headers = headers
        self.body = body
    def do_request():
        # @TODO

class Task:
    def __init__(self, raw_task):
        self.raw_task = raw_task # This is the raw JSON for a task

        # Initialize http requests
        self.http_requests = []

        # Parse the json
        tasks_loaded = json.loads(self.raw_task)
        for request in tasks_loaded["Requests"]:
            method = request["Method"]
            host = request["Host"]
            path = request["Path"]
            headers = request["Headers"]
            body = request["Body"]
            http_request_deserialized = HTTPRequestStruct(method, host, path, headers, body)
            self.http_requests.append(http_request_deserialized)

class TaskManager(Task):
    def __init__(self):
        self.tasks = []
    def push_task(self, Task):
        self.tasks.append(Task)
    def do_tasks(self):
        # @TODO

@app.route("/")
def Index():
    return "Hello, world!"

@app.route("/uploadtask")
def UploadTask():
    if request.method == "POST":
        r_type = request.form["Type"]
        r_ID = request.form["ID"]
        r_Message = request.form["Message"]
        r_MessageBinary = request.form["MessageBinary"]
        r_Version = request.form["Version"]

@app.route("/ping")
def Ping():
    # @TODO

@app.route("/pong")
    # @TODO


if __name__ == "__main__":
    app.run(debug=False, port=PORT)