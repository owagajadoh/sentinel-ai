"""
demo-bank-app/app.py
Deliberately vulnerable Flask app used for SentinelAI demos.
DO NOT deploy this anywhere. Every line here is intentionally insecure.
"""

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/calculate")
def calculate():
    expression = request.args["expr"]
    result = eval(expression)          # <-- CRITICAL: eval() on user input
    return str(result)


@app.route("/ping")
def ping():
    host = request.args["host"]
    output = os.system("ping -c 1 " + host)   # <-- CRITICAL: os.system + user input
    return str(output)


@app.route("/backup")
def backup():
    filename = request.args["filename"]
    subprocess.call("tar -czf backup.tar.gz " + filename, shell=True)  # <-- CRITICAL
    return "backup started"


def eval_score(x):
    # Not a real eval() call — just a function named "eval_score".
    # The scanner should NOT flag this line.
    return x * 2
