from flask import Flask, request, jsonify
import pickle
from ssl_checker import SSLChecker
import os
import scipy


app = Flask(__name__)
ssl_checker = SSLChecker()

dir_name = os.path.dirname(os.path.abspath(__file__))

# Load the ML model and the vectorizer
filename = "logistic.pickle"
loaded_model = pickle.load(open(filename, "rb"))
loaded_vectorizer = pickle.load(open(dir_name+'/vectorizer.pickle',"rb"))

@app.route('/predict', methods=['POST'])
def predict():
    # Get the data from the POST request
    url = request.args['url']
    # Transform the input data using the vectorizer
    test_x_d = loaded_vectorizer.transform([url])
    # Use the loaded ML model to make predictions
    y_pred = loaded_model.predict(test_x_d)
    # Return the prediction result as a JSON response
    return jsonify({'prediction': y_pred[0]})

@app.route('/check_ssl', methods=['POST'])
def check_ssl():
    hosts = request.args.getlist('hosts')
    if not hosts:
        return {'error': 'Please provide a list of hosts to check.'}, 400
    results = {}
    for host in hosts:
        try:
            host, port = ssl_checker.filter_hostname(host)
            cert = ssl_checker.get_cert(host, port)
            cert_info = ssl_checker.get_cert_info(host, cert)
            cert_info['tcp_port'] = int(port)
            results[host] = cert_info
        except Exception as e:
            results[host] = {'error': str(e)}
    return results, 200

if __name__ == '__main__':
    app.run()

