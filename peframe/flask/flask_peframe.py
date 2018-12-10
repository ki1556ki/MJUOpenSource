from flask import Flask, render_template, request
from werkzeug import secure_filename
 
app = Flask(__name__)    


@app.route('/fileUpload', methods = ['GET', 'POST'])
def upload_file():
    return render_template('result.html')
        
 
@app.route('/')
def home():
    return render_template('home.html')
 
if __name__ == '__main__':
    app.run(debug=True)