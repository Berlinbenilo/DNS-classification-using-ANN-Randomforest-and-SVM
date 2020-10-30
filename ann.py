import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split


file = pd.read_csv('kddcup99_csv.csv')

df = pd.DataFrame(file)
print(df.head(5))

# converting label format
# print(df['label'].unique())
df['label'] = df['label'].replace(['buffer_overflow','loadmodule', 'perl', 'neptune', 'smurf',
                 'guess_passwd', 'pod', 'teardrop', 'portsweep', 'ipsweep', 'land', 'ftp_write',
                 'back', 'imap', 'satan', 'phf', 'nmap', 'multihop', 'warezmaster', 'warezclient',
                 'spy', 'rootkit'],'malicious')
df['label'] = df['label'].replace('normal','benign')
print(df['label'])


# total benign and malicious
plt.figure(1)
sns.countplot(x='label',data = df)
plt.show()
plt.figure(2)
sns.countplot(x='protocol_type',data = df,hue='label')
plt.show()
print(sorted(df['service'][:10].unique()))
plt.figure(num=3,figsize=(15,4))
subgrade_order = sorted(df['flag'].unique())
sns.countplot(x='flag',data=df,order = subgrade_order,palette='flag',hue='label' )
plt.show()

print(list(df.columns) )
df = df.drop(columns=['duration','service', 'flag','land','wrong_fragment', 'urgent', 'hot','wrong_fragment',
                      'urgent', 'hot', 'num_failed_logins','lnum_compromised', 'lroot_shell', 'lsu_attempted',
                      'lnum_shells', 'lnum_access_files', 'lnum_outbound_cmds', 'is_host_login', 'is_guest_login',
                      'lnum_root', 'lnum_file_creations'])
print(df)

# converting all protocol to integer
protocol_type = {'tcp':1,'udp':2,'icmp':3}
df.protocol_type = [protocol_type[item] for item in df.protocol_type]


df['label'] = df['label'].replace('benign',0)
df['label'] = df['label'].replace('malicious',1)

print(df)
print(df.isnull().sum())

## train test split
X = df.drop('label',axis=1).values
y = df['label'].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=101)



# scaling data
from sklearn.preprocessing import MinMaxScaler
scalar = MinMaxScaler()
scalar.fit(X_train)

X_train = scalar.transform(X_train)
X_test = scalar.transform(X_test)

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense,Activation,Dropout

from tensorflow.keras.callbacks import EarlyStopping
print(X_train.shape)

model = Sequential()

model.add(Dense(units=30,activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(units=15,activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(units=1,activation='sigmoid'))

model.compile(loss='binary_crossentropy',optimizer='adam')

early_stop = EarlyStopping(monitor='val_loss', mode='min', verbose=1, patience=25)
model.fit(x=X_train,
          y=y_train,
          epochs=600,
          validation_data=(X_test, y_test), verbose=1,
          callbacks=[early_stop]
          )

model_loss = pd.DataFrame(model.history.history)
model_loss.plot()
plt.show()


model.save_weights("model.h5")
print("Saved model to disk")

predictions = model.predict_classes(X_test)

from sklearn.metrics import classification_report,confusion_matrix
print(classification_report(y_test,predictions))

print(confusion_matrix(y_test,predictions))

## taking first row
single_house = df.drop('label',axis=1).iloc[0]

single_house = scalar.transform(single_house.values.reshape(-1, 23))
print(model.predict(single_house))
if model.predict(single_house) == 0:
    print("Benign")
else:
    print("Malicious")
