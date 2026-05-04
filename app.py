import os
import shutil
import time
from flask import Flask, render_template, request, jsonify, send_from_directory

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
MAX_SIZE = 10 * 1024 * 1024 * 1024  # 10GB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_SIZE

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def delete_old_files():
    now = time.time()
    for filename in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.stat(path).st_mtime < now - 86400:
            if os.path.isfile(path):
                os.remove(path)
            else:
                shutil.rmtree(path)

@app.route('/')
def index():
    delete_old_files()
    return render_template('index.html')

@app.route('/upload_files', methods=['POST'])
def upload_files():
    files = request.files.getlist('files')
    saved = []

    for file in files:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(path)
        saved.append(file.filename)

    return jsonify({"message": "Files uploaded", "files": saved})

@app.route('/upload_folder', methods=['POST'])
def upload_folder():
    files = request.files.getlist('folder')
    saved = []

    for file in files:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file.save(path)
        saved.append(file.filename)

    return jsonify({"message": "Folder uploaded", "files": saved})

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/text')
def text():
    return render_template('text.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
