from flask import Flask, jsonify
import json

app = Flask(__name__)

@app.route("/")
def home():
    """ Load scan results from JSON file and return as JSON """
    try:
        with open("results.json") as f:
            data = json.load(f)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"error": "No scan results found. Run a scan first!"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
