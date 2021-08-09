#!/usr/bin/env python
# coding: utf-8



import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier as RFC
from sklearn.neighbors import KNeighborsClassifier as KNN
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.svm import SVC




oldx = pd.read_csv("X_train_res.csv")
oldx.drop(columns=["src","dst"], inplace=True)


# # Training



X_train = pd.read_csv("X_train_res.csv")
y = pd.read_csv("y_train_res.csv")
y = y["output"]




names = X_train[["src","dst"]]
X = X_train.drop(columns = ["src", "dst"])




model = RFC()
scores = cross_val_score(model, X, y, cv=10, scoring='f1_macro')
print(scores)
print(sum(scores) / 10)


# # Prediction



X_train , X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 100, stratify=y)
print('Splitting done')
model = RFC(n_estimators=1000)
model.fit(X_train, y_train)
print('Training done')
y_pred = model.predict(X_test)
print('Prediction generated, creating classification report and confusion matrix........\n')

print(accuracy_score(y_test,y_pred), '\n')
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))






