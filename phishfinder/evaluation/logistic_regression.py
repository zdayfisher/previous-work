from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn import preprocessing
from sklearn.preprocessing import OneHotEncoder
import datetime
import pandas as pd
import numpy as np
import tldextract

from os.path import dirname, join as pjoin


def is_ip(url):
    '''
    Check if URL contains an IP address inside
    '''
    s =  url.find('//')
    if s != -1 and len(url) >= s + 14:
        url = url[s+2:s+14]
    return 1 if url.replace('.', '').isnumeric() else 0

def suspicious_characters(url):
    '''
    Check if domain name contains suspicious characters such as '@'
    '''
    return 1 if '@' in url else 0

def use_http(url):
    '''
    Check if http:// is used instead of https://
    '''
    return 1 if 'http://' in url else 0

def redirects(url):
    '''
    Check if URL redirects you to another final URL
    '''
    return False

def process_input_data():
    '''
    Returns the dataframe containing information about benign and malicious URLs
    '''
    df = pd.read_csv(pjoin(dirname(__file__), "data/original_lists/data-benign.csv"))
    df['phishing'] = df.apply(lambda row: 0, axis = 1)

    df_malicious = pd.read_csv(pjoin(dirname(__file__), "data/original_lists/data-malicious.csv"))
    df_malicious['phishing'] = df_malicious.apply(lambda row: 1, axis = 1)

    df = df.append(df_malicious, ignore_index = True)

    #extract domain info and apply heuristics based on that info
    df['subdomain'] = df.apply(lambda row: tldextract.extract(row['link']).subdomain, axis = 1)
    df['domain'] = df.apply(lambda row: tldextract.extract(row['link']).domain, axis = 1)
    df['suffix'] = df.apply(lambda row: tldextract.extract(row['link']).suffix, axis = 1)
    df['insecure_protocol'] = df.apply(lambda row: use_http(row['link']), axis = 1)
    df['is_ip'] = df.apply(lambda row: is_ip(row['link']), axis = 1)
    df['suspicious_chars'] = df.apply(lambda row: suspicious_characters(row['link']), axis = 1)
    df['domain_length'] = df.apply(lambda row: len(row['subdomain']) + len(row['domain']), axis = 1)

    #shuffle the dataframe
    df = df.sample(frac=1).reset_index(drop=True)

    return df

#Model Evaluation Metrics

def recall(actual_tags, predictions, class_of_interest):
    '''
    Calculates the recall for a specific class, given the ground truth and predicted values.
    '''
    total_found = 0
    for i in range(len(actual_tags)):
        if (actual_tags[i] == class_of_interest and actual_tags[i] == predictions[i]):
            total_found += 1
    return total_found / np.count_nonzero(actual_tags == class_of_interest)

def precision(actual_tags, predictions, class_of_interest):
    '''
    Calculates the precision for a specific class, given the ground truth and predicted values.
    '''
    total_found = 0
    for i in range(len(actual_tags)):
        if (actual_tags[i] == class_of_interest and actual_tags[i] == predictions[i]):
            total_found += 1
    return total_found / np.count_nonzero(predictions == class_of_interest)

def accuracy(actual_tags, predictions):
    '''
    Calculates the average number of correct predictions.
        - actual_tags: The ground truth
        - predictions: What the model predicts
    '''
    total_found = 0
    for i in range(len(actual_tags)):
        if (actual_tags[i] == predictions[i]):
            total_found += 1
    return total_found / len(predictions)

def train_and_evaluate_lr():
    '''
    Returns the accuracy, precision and recall of linear regression model
    '''
    X = process_input_data()
    ohe = OneHotEncoder(sparse=False, handle_unknown='ignore')

    y = X.pop('phishing').values
    feature_set = {'insecure_protocol', 'is_ip', 'suspicious_chars', 'domain_length', 'suffix'}
    X = X[feature_set].copy()
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size = 0.2, random_state=2)

    ohe.fit(X_train)
    X_train_encoded = ohe.transform(X_train)
    X_val_encoded = ohe.transform(X_val)

    clf_lr = LogisticRegression(solver='lbfgs', max_iter=1000, random_state=1).fit(X_train_encoded, y_train)
    ##lr_train_predictions = clf_lr.predict(X_train_encoded)
    
    lr_val_predictions = clf_lr.predict(X_val_encoded)
    return accuracy(y_val, lr_val_predictions), precision(y_val, lr_val_predictions, 1), recall(y_val, lr_val_predictions, 1)


def train_and_evaluate_mlp():
    '''
    Returns the accuracy, precision and recall of multilayer perceptron model
    '''
    X = process_input_data()
    ohe = OneHotEncoder(sparse=False, handle_unknown='ignore')
   
    y = X.pop('phishing').values
    
    feature_set = {'insecure_protocol', 'is_ip', 'suspicious_chars', 'domain_length', 'suffix'}
    
    X = X[feature_set].copy()
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size = 0.2, random_state=2)

    ohe.fit(X_train)
    X_train_encoded = ohe.transform(X_train)
    X_val_encoded = ohe.transform(X_val)

    clf_mlp = MLPClassifier(solver='lbfgs', alpha=1e-4, hidden_layer_sizes=(150, 150), random_state=5, max_iter=120, learning_rate_init=0.01, warm_start=True)
    clf_mlp.fit(X_train_encoded, y_train)
    #mlp_train_predictions = clf_mlp.predict(X_train_encoded)

    mlp_val_predictions = clf_mlp.predict(X_val_encoded)
    return accuracy(y_val, mlp_val_predictions), precision(y_val, mlp_val_predictions, 1), recall(y_val, mlp_val_predictions, 1)

if __name__ == '__main__':
    print(train_and_evaluate_mlp())
    print(train_and_evaluate_lr())