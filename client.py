from flask import Flask

app = Flask(__name__)

PORT = "4600"

@app.route("/")
def Index():
    return "Hello, world!"

if __name__ == "__main__":
    app.run(debug=False, port=PORT)