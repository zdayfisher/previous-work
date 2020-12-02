from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import datetime
import pandas as pd
import numpy as np
import tldextract


def is_ip(url):
    s =  url.find('//')
    if s != -1 and len(url) >= s + 14:
        url = url[s+2:s+14]
    return 1 if url.replace('.', '').isnumeric() else 0

def suspicious_characters(url):
    '''
    Checking if domain name contains suspicious characters such as '@'
    '''
    return 1 if '@' in url else 0

def use_http(url):
    '''
    Checking if http:// is used instead of https://
    '''
    return 1 if 'http://' in url else 0

def is_short_url(url):
    return False

def train_model(X_train, y_train):
    clf_lr = LogisticRegression(solver='lbfgs', max_iter=1000, random_state=1).fit(X_train, y_train)
    lr_train_predictions = clf_lr.predict(X_train)
    return clf_lr

def predict_results(clf_lr, X_test, y_test):
    lr_test_predictions = clf_lr.predict(X_test)
    return lr_test_predictions

def process_input_data():
    df = pd.read_csv("pkg/evaluation/training_data/data-benign.csv")
    df['phishing'] = df.apply(lambda row: 0, axis = 1)

    df_malicious = pd.read_csv("pkg/evaluation/training_data/data-malicious.csv")
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
        - actualTags: The ground truth
        - predictions: What the model predicts
    '''
    total_found = 0
    for i in range(len(actual_tags)):
        if (actual_tags[i] == predictions[i]):
            total_found += 1
    return total_found / len(predictions)

def train_and_evaluate():
    X = process_input_data()
    y = X.pop('phishing').values
    feature_set = {'insecure_protocol', 'is_ip', 'suspicious_chars', 'domain_length'}
    X = X[feature_set].copy()
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size = 0.2, random_state=2)

    clf_lr = LogisticRegression(solver='lbfgs', max_iter=1000, random_state=1).fit(X_train, y_train)
    lr_train_predictions = clf_lr.predict(X_train)
    print(accuracy(y_train, lr_train_predictions))
    
train_and_evaluate()