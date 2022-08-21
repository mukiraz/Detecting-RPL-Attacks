# -*- coding: utf-8 -*-
"""
Created on Wed Feb 24 12:23:38 2021

These codes were created for my master's thesis "Comparison of Machine Learning Algorithms to Detect RPL-Based IoT Devices Vulnerability".

See README file for details.

After obtaining the meaningful data from raw dataset, (see for details https://en.mukiraz.com/2022/07/making-raw-data-meaningful/)
these python scripts are used for detecting attacks from meaningful dataset.

Basically, the program gets two csv files.

One file includes the data with benign IoT motes. The other file includes the data with a malicious mote.
Each dataset is labelled with 1 and 0. (see https://github.com/mukiraz/Detecting-RPL-Attacks/blob/main/IoT_Dataset.py)

Dataset with a malicious mote labelled with 1.
Dataset with benign motes are labelled with 0.

Even before machine learning was performed, an equal amount of rows were taken from normal and vulnerable data sets. 
For this, the number of rows of the data set with the least number of rows from the normal or vulnerable data sets 
obtained from the 60th second was taken as the basis, and the same amount of sales was taken from the other data set. 
Thus, it is aimed to obtain a balanced amount of data. 

Source and destination IP addresses are extracted from the datasets before the normalization process 
so that the machine does not learn whether there is an attack based on the source and destination IP addresses. 
Subsequently, the data were normalized.  This has been done with the StandardScaler library in python.

Subsequently, the dataset was split into test and training datasets in the amount of 2/3. (2/3 training, 1/3 testing).

After this stage, the data sets will be trained and tested with different machine learning algorithms 
and the most appropriate machine learning algorithm to be used in the detection of 
Flooding, Version Number Increase and Decreased Rank Attack will be determined in the RPL protocol. 

For this purpose, six types of machine learning algorithms were tested. 
These are the algorithms 

1. Logistic Regression Classification, 
2. Decision Trees, 
3. Random Forest, 
4. Navie Bayes, 
5. KNN Classifier and 
6. Artificial Neural Networks. 

After the execution of the experiments, the accuracy rate and training time will be compared on the values.
The accuracy rate (AR) is calculated as in equation 3.19, and TP is True Positive, TN is True Negative, FP is False Positive, and FN is False Negative.


@author: Murat Ugur KIRAZ
"""

import pandas as pd
import time
from sklearn.model_selection import train_test_split # For splitting the data
from sklearn.preprocessing import StandardScaler # For normalizing the data
from sklearn.metrics import confusion_matrix # For creating the confurion matrix
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
# For Deep learning
from tensorflow import keras
from tensorflow.keras import layers


"""
 For the performance of an algorithm, we need Big O notation or big omega notation. 
 Time is not an indicator for performance of an algorithm. However in this experiment
 we used time as an indicator that shows the performance. That is why it will be hard to calculate each 
 algortihm's performance with Big O notation or big omega notation
"""
# This function gives us the time value in miliseconds.
def current_milli_time():
    return round(time.time() * 1000)

# This function calculates the accuracy rate of a confusion matrix.
def calculate_AR(confusion_matrix):
    return (confusion_matrix[0][0] + confusion_matrix[1][1]) / (confusion_matrix[0][0] + confusion_matrix[0][1] + confusion_matrix[1][0] + confusion_matrix[1][1])

def print_values(algorithm:str, accuracy_rate:float, training_time:int):
    print(algorithm, "Accuracy rate", accuracy_rate, "Training time:", training_time)


# Obtaining dataset with malicious mote, Please tahe attention that the files must be 
# in the same folder with this python file. 
flnme1 = "DR-9N1M1R.csv"
# Obtaining dataset with normal motes
flnme2 = "DR-10N1R.csv"

# We create the pandas datasets.
df1 = pd.read_csv("Results/New/"+flnme1, sep=";")
df2 = pd.read_csv("Results/New/"+flnme2, sep=";")

# Obtaining row numbers of datasets (This is why we desire to have same amount of data rows.)
len1 = len(df1)
len2 = len(df2)

# This if block obtains equal rows from each dataset
if len1 < len2:
    df2 = df2.iloc[0:len1]
else:
    df1 = df1.iloc[0:len2]
    
  
# We are merging two datasets
frames = [df1, df2]
df = pd.concat(frames)

# Source and destination IP addresses are extracted from the datasets before the normalization process.
X=df.iloc[:,3:16].values
y=df.iloc[:,16:17].values.ravel()

# The dataset was split into test and training datasets in the amount of 2/3. (2/3 training, 1/3 testing).
x_train,x_test,y_train,y_test=train_test_split(X,y,test_size=0.33,random_state=0)


# Normalizing the data
sc=StandardScaler()
x_train = sc.fit_transform(x_train)
x_test = sc.transform(x_test)

###### Scripts for Logistic regression
lrstart_time = current_milli_time()  # Obtaining initial time of the training
logr = LogisticRegression(random_state=0) # Creating the logistic regression object
logr.fit(x_train,y_train) # Training the data
lrend_time = current_milli_time()  # Obtaining ending time of the training
LRduration = lrend_time - lrstart_time # Calculating the duration
y_pred_lr = logr.predict(x_test) # Predicting data
cm_lr = confusion_matrix(y_test,y_pred_lr) # Creating confusion matrix
ar_lr = calculate_AR(cm_lr) # Calculating accuracy rate.


###### Scripts for Random Forest Classifation
rfstart_time = current_milli_time() # Obtaining initial time of the training
rfc = RandomForestClassifier(n_estimators=8, criterion='entropy') # Creating the Random Forest Classifation object
rfc.fit(x_train,y_train) # Training the data
rfend_time = current_milli_time() # Obtaining ending time of the training
RFduration = rfend_time - rfstart_time # Calculating the duration
y_pred_rfc = rfc.predict(x_test) # Predicting data
cm_rfc = confusion_matrix(y_test,y_pred_rfc) # Creating confusion matrix
ar_rfc = calculate_AR(cm_rfc) # Calculating accuracy rate.


###### Scripts for Decision Tree Classifier
dtstart_time = current_milli_time() # Obtaining initial time of the training
dtc=DecisionTreeClassifier(criterion='entropy') # Creating the Decision Tree Classifier object
dtc.fit(x_train,y_train) # Training the data
dtend_time = current_milli_time() # Obtaining ending time of the training
DTduration = dtend_time - dtstart_time # Calculating the duration
y_pred_dtc = dtc.predict(x_test) # Predicting data
cm_dtc = confusion_matrix(y_test,y_pred_dtc) # Creating confusion matrix
ar_dtc = calculate_AR(cm_dtc) # Calculating accuracy rate.



###### Scripts for Naive Bayes Classifier
nbstart_time = current_milli_time() # Obtaining initial time of the training
gnb = GaussianNB() # Creating the Naive Bayes Classifier object
gnb.fit(x_train,y_train) # Training the data
nbend_time = current_milli_time() # Obtaining ending time of the training
NBduration = nbend_time - nbstart_time # Calculating the duration
y_pred_nb = gnb.predict(x_test) # Predicting data
cm_nb = confusion_matrix(y_test,y_pred_nb) # Creating confusion matrix
ar_nb = calculate_AR(cm_nb) # Calculating accuracy rate.


###### Scripts for KNN Classifier
knnstart_time = current_milli_time() # Obtaining initial time of the training
knn = KNeighborsClassifier() # Creating the KNN Classifier object
knn.fit(x_train,y_train) # Training the data
knnend_time = current_milli_time() # Obtaining ending time of the training
knnduration=knnend_time - knnstart_time # Calculating the duration
y_pred_knn = knn.predict(x_test) # Predicting data
cm_knn = confusion_matrix(y_test,y_pred_knn) # Creating confusion matrix
ar_knn = calculate_AR(cm_knn) # Calculating accuracy rate.


###### Scripts for Deep learning
# Creating the Deep learning object
# We established 13 input, that is why we have 13 columns. the other layers are established with 50, 100, 300, 100, 50, 1 layers repectively.
model = keras.Sequential(
    [
        keras.Input(shape=(13)),
        layers.Dense(50, activation="relu"),
        layers.Dense(100, activation="relu"),
        layers.Dense(300, activation="relu"),
        layers.Dense(100, activation="relu"),
        layers.Dense(50, activation="relu"),
        layers.Dense(1, activation="sigmoid"),
    ]
)
start_time = current_milli_time() # Obtaining initial time of the training
model.compile(optimizer="Nadam", loss="binary_crossentropy", metrics=['binary_accuracy'])
model.fit(x_train,y_train,epochs=60) # Training the data
end_time = current_milli_time() # Obtaining ending time of the training
DLduration = end_time - start_time # Calculating the duration
y_pred_dl = model.predict(x_test) # Predicting data
y_pred_dl = (y_pred_dl>0.7)
cm_dl = confusion_matrix(y_test,y_pred_dl) # Creating confusion matrix
ar_dl = calculate_AR(cm_dl) # Calculating accuracy rate.

# Printing the results
print("")
print_values("Logistic Regression", ar_lr, LRduration)
print_values("Random Forest Classifation", ar_rfc, RFduration)
print_values("Decision Tree Classifier", ar_dtc, DTduration)
print_values("Naive Bayes Classifier", ar_nb, NBduration)
print_values("KNN Classifier", ar_knn, knnduration)
print_values("Deep Learning", ar_dl, DLduration)


"""
Also the Fuzzy Pattern Tree Classifier was tested for experiments.
fptstart_time=current_milli_time()
from fylearn.fpt import FuzzyPatternTreeClassifier     
fpc4=FuzzyPatternTreeClassifier()
fpc4.fit(x_train,y_train)
y_pred_fpc4 = fpc4.predict(x_test)

cm_fpc4=confusion_matrix(y_test,y_pred_fpc4)

fptend_time=current_milli_time()
FPTduration=fptend_time-fptstart_time

"""
