"""
Main evaluation module.

This module provides the evaluate function which acts as a pipeline for
the evaluation module.

Purpose
-------
Process domain  data provided by discovery module.
Train the Logistic Regression or Multi-Layer Perceptron Classifier
using the processed data and evaluate model's performance based on its
accuracy, precision and recall.
Use the trained model to decide whether unclassified domains are benign
or phishing.

Non-Public Functions
--------------------

.. note:: Non-public functions are not part of this API documentation.
    More information about these functions can be found in the source code
    in the form of docstrings.

- `is_ip`
- `suspicious_characters`
- `use_http`
- `redirects`
- `process_input_data_domain`: Processes csv file containing training data with domain information.
- `process_unknown_data_domain`: Processes csv file containing unclassified data with domain information.
- `prep_domain_data`: Selects a limited feature set for known and unknown data and performs One-Hot Encoding
- `train_lr`: Creates a Logistic Regression model and peerfmorms training using provided training data.
- `train_mlp`: Creates a Multi-Layer Perceptron model and peerfmorms training using provided training data.
- `recall`: Calculates the recall for a specific class, given the ground truth and predicted values.
- `precision`: Calculates the precision for a specific class, given the ground truth and predicted values.
- `accuracy`: Calculates the accuracy for a specific class, given the ground truth and predicted values.
- `evaluate`: Evaluates accuracy, precision and recall of a model using provided testing data.
- `is_benign`: Returns a string representation for benign and malicious classes
"""

from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn import preprocessing
from sklearn.preprocessing import OneHotEncoder
import datetime
import pandas as pd
import numpy as np
import tldextract
from tqdm import tqdm

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

def process_input_data_domain(max_rows):
    '''
    Returns the dataframe containing information about benign and malicious domains
    '''
    df = pd.read_csv(pjoin(dirname(__file__), "data/training_data/benign_certs.csv"))
    df['phishing'] = df.apply(lambda row: 0, axis = 1)

    df_malicious = pd.read_csv(pjoin(dirname(__file__), "data/training_data/malicious_certs.csv"))
    df_malicious['phishing'] = df_malicious.apply(lambda row: 1, axis = 1)

    df = df.append(df_malicious, ignore_index = True)

    df.dropna(inplace=True)
    
    df['suspicious-chars'] = df.apply(lambda row: suspicious_characters(row['domain-name']), axis = 1)
    df['domain-length'] = df.apply(lambda row: len(row['domain-name']), axis = 1)

    #shuffle the dataframe
    df = df.sample(frac=1).reset_index(drop=True)
    df = df.iloc[:max_rows, :]

    return df

def process_unknown_data_domain(df):
    '''
    Returns the dataframe retrieved by discovery module that needs to be classified.
    '''
    
    df['suspicious-chars'] = df.apply(lambda row: suspicious_characters(row['domain-name']), axis = 1)
    df['domain-length'] = df.apply(lambda row: len(row['domain-name']), axis = 1)

    #shuffle the dataframe
    #df = df.sample(frac=1).reset_index(drop=True)
    df = df.iloc[:100, :]

    return df


def prep_domain_data(discovery_results, max_rows):
    '''
    Return the One-Hot Encoded version of the train and test split dataframes for the following featureset of the domain certificate data:
        - 'suspicious-chars'
        - 'domain-length'
        - 'issuer-name'
        - 'issuer-country'
        - 'cert-duration'
        - 'issuer-country-count'
    '''
    feature_set = {'suspicious-chars', 'domain-length', 'issuer-name', 'issuer-country', 'cert-duration', 'issuer-country-count'}
    X = process_input_data_domain(max_rows)
    X_unknown = process_unknown_data_domain(discovery_results)

    ohe = OneHotEncoder(sparse=False, handle_unknown='ignore')
   
    y = X.pop('phishing').values

    X1 = X.groupby('domain-name')['issuer-country'].nunique()  
    X = X.join(X1, on='domain-name', rsuffix='-count')


    X2 = X_unknown.groupby('domain-name')['issuer-country'].nunique()
    X_unknown = X_unknown.join(X2, on='domain-name', rsuffix='-count')
    
    X = X[feature_set].copy()
    X_unknown = X_unknown[feature_set].copy()

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size = 0.1, random_state=2)
    ohe.fit(X_train)
    X_train_encoded = ohe.transform(X_train)
    X_val_encoded = ohe.transform(X_val)
    X_unknown_encoded = ohe.transform(X_unknown)

    return X_train_encoded, y_train, X_val_encoded, y_val, X_unknown_encoded

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

def train_lr(X_train, y_train):
    '''
    Returns a Logistic Regression classifier trained based on provided data.
    '''
    clf_lr = LogisticRegression(solver='lbfgs', max_iter=1000, random_state=1).fit(X_train, y_train)
    return clf_lr

def train_mlp(X_train, y_train):
    '''
    Returns a Multi-Layer Perceptron classifier trained based on provided data
    '''
    clf_mlp = MLPClassifier(solver='lbfgs', alpha=1e-4, hidden_layer_sizes=(200, 200), random_state=5, max_iter=200, early_stopping=True, learning_rate_init=0.01, verbose=True, warm_start=True)
    clf_mlp.fit(X_train, y_train)

    return clf_mlp

def evaluate(model, X_val, y_val):
    '''
    Returns model's accuracy, precision, and recall for class 1 (Malicious) data.
    '''
    predictions = model.predict(X_val)
    return accuracy(y_val, predictions), precision(y_val, predictions, 1), recall(y_val, predictions, 1)

def is_benign(row):
    '''
    Returns string representation for 1 (Malicious) and 0 (Benign) classes
    '''
    if row == 1:
        return 'malicious'
    else:
        return 'benign'

def evaluation(discovery_results, max_rows = 50000):
    """
    Trains a machine learning model based on known benign and malicious
    domains. Evaluates the performance of the model. Uses the model to classify 
    previsouly unknown domains.

    Parameters
    ----------
    discovery_results: pandas.DataFrame
        Pandas DataFrame with information found about each generated
        possible phishing domain.

    max_rows: int
        Maximum number of rows to be used for training the model.

    Returns
    -------
    Returns: pandas.DataFrame
        Returns a pandas DataFrame with information found about each generated
        possible phishing domain and their classfication as benign or malicious.
    """
    if discovery_results.empty:
        discovery_results = pd.read_csv(pjoin(dirname(__file__), "data/test_data/netflix_test.csv"))
    
    for i in tqdm(range(1)):
        X_train, y_train, X_val, y_val, X_unknown = prep_domain_data(discovery_results, max_rows)
    mlp_model = train_mlp(X_train, y_train)


    train_accuracy, train_prec, train_recall = evaluate(mlp_model, X_train, y_train)
    test_accuracy, test_prec, test_recall = evaluate(mlp_model, X_val, y_val)
    
    print("Accuracy for training data:", train_accuracy)
    print("Precision for training data:", train_prec)
    print("Recall for training data:", train_recall)
    print("Accuracy for test data:", test_accuracy)
    print("Precision for test data:", test_prec)
    print("Recall for test data:", test_recall)
    
    predictions = mlp_model.predict(X_unknown)
    
    unknown_df = process_unknown_data_domain(discovery_results)
    unknown_df['prediction'] = predictions
    unknown_df['prediction'] = unknown_df.apply(lambda row: is_benign(row['prediction']), axis = 1)

    print(unknown_df.head(10))


    return unknown_df

#if __name__ == '__main__':
#    evaluation(pd.DataFrame({'A' : []}))
