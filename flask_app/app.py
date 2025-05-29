from flask import Flask, request, redirect,render_template
import psycopg2
from datetime import datetime
app = Flask(__name__)



@app.route('/')
def helloworld():
    return render_template('index.html')


def insert_feedback(data):
    try:
        conn = psycopg2.connect(
            host= 'my-postgres',
            database= 'mydb',
            user= 'admin',
            password= 'secret'
        )
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO user_feedback (
                name, network_type, vpn_proxy, device_ownership, device_type,
                trust_level, surprise_flagged, browser, traffic_type, user_label
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, data)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error inserting feedback: {e}")

@app.route("/submit-feedback", methods=["GET", "POST"])
def feedback():
    submitted = False
    if request.method == "POST":
        data = (
            request.form.get("name"),
            request.form.get("network_type"),
            request.form.get("vpn_proxy"),
            request.form.get("device_ownership"),
            request.form.get("device_type"),
            request.form.get("trust_level"),
            request.form.get("surprise_flagged"),
            request.form.get("browser"),
            request.form.get("traffic_type"),
            request.form.get("user_label")
        )
        insert_feedback(data)
        submitted = True
    return render_template("index.html", submitted=submitted)


if __name__ == '__main__':
    app.run(host = '0.0.0.0',port = 5000)

