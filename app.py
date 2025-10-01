from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")  # 網站根目錄
def index():
    return render_template("index.html")  # 回傳 templates/index.html

if __name__ == "__main__":
    app.run(debug=True)
# 啟動 Flask 應用程式，並開啟除錯模式