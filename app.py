from flask import Flask, render_template, request, flash, redirect
from config import *
from login_packet_generator import generate_login_packet
from query_server import query_server

app = Flask(__name__)
app.secret_key = 'hi'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/access', methods=['POST'])
def probe():
    username = request.form.get('username')
    password = request.form.get('password')
    packet = generate_login_packet(username,password)
    response = query_server(packet)
    if response != RESP_SUCCESS:
        flash("Invalid username or password.", "error")
        return redirect('/')
    return render_template('access.html',name=username)

if __name__ == '__main__':
    app.run(port=5000, debug=True)