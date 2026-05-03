import os
import uuid
import time
import threading
from flask import Flask, render_template, request, send_from_directory

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif',
    'mp4', 'pdf', 'docx', 'xlsx', 'txt'
}

file_data = {}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        file = request.files.get("file")

        if not file:
            return "No file selected!"

        if not allowed_file(file.filename):
            return "Invalid file type!"

        unique_id = str(uuid.uuid4())
        filename = unique_id + "_" + file.filename
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        file.save(filepath)

        file_data[unique_id] = {
            "filename": filename,
            "time": time.time()
        }

        link = f"/download/{unique_id}"
        full_link = request.host_url.rstrip("/") + link

        return f"""
        <div class="success-box">
            <p class="success-text">Upload Successful!</p>

            <input type="text" value="{full_link}" id="linkBox" readonly>

            <button onclick="copyLink()">Copy Link</button>

            <a href="{link}" target="_blank" class="download-btn">
                Download File
            </a>
        </div>
        """

    return render_template("index.html")


@app.route("/download/<file_id>")
def download_file(file_id):
    if file_id in file_data:
        file_info = file_data[file_id]

        if time.time() - file_info["time"] > 900:
            try:
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], file_info["filename"]))
            except:
                pass
            del file_data[file_id]
            return "Link expired!"

        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            file_info["filename"],
            as_attachment=True
        )

    return "Invalid or expired link!"


def delete_expired_files():
    while True:
        current_time = time.time()
        to_delete = []

        for file_id, data in file_data.items():
            if current_time - data["time"] > 900:
                try:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], data["filename"]))
                except:
                    pass
                to_delete.append(file_id)

        for file_id in to_delete:
            del file_data[file_id]

        time.sleep(60)


if __name__ == "__main__":
    thread = threading.Thread(target=delete_expired_files)
    thread.daemon = True
    thread.start()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)