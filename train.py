
from data_loader import *
from sklearn.svm import OneClassSVM

X_train = pcapng_data_loader("full1.pcapng")+pcapng_data_loader("full5.pcapng")
X_test = pcap_data_loader("error.pcap")

clf = OneClassSVM(kernel='linear', nu=0.001).fit(X_train)
print(clf.predict(X_test))
print(clf.predict(X_train))



