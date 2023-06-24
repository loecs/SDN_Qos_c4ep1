import time
import pandas as pd
import numpy as np
import random
import matplotlib
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from keras.models import Sequential
from keras.layers import Dense,LSTM
import pymysql
T1 = time.process_time()
my_seed = 2017
np.random.seed(my_seed)
random.seed(my_seed)
tf.random.set_seed(my_seed)



df2='45.xlsx'
data2=pd.read_excel(df2)
# print(data2.head(10))

# 创建一个Series对象
a = data2["throughput"]
b = data2["delay"]
c = data2["jitter"]
d = data2["loss"]
# 将Series转换为ndarray
arr_a = a.to_numpy()
arr_b = b.to_numpy()
arr_c = c.to_numpy()
arr_d = d.to_numpy()
# 输出数组
# print(arr)

# type(arr)

matplotlib.rcParams['font.family'] = 'SimHei'
all_data1=arr_a
all_data2=arr_b
all_data3=arr_c
all_data4=arr_d
# type(all_data)
from sklearn.preprocessing import MinMaxScaler
stand_scaler = MinMaxScaler()
all_data1 = stand_scaler.fit_transform(all_data1.reshape(-1,1))
all_data2 = stand_scaler.fit_transform(all_data2.reshape(-1,1))
all_data3 = stand_scaler.fit_transform(all_data3.reshape(-1,1))
all_data4 = stand_scaler.fit_transform(all_data4.reshape(-1,1))

#sequence_len = 10 #原来的
sequence_len = 5 #最适合
X1 = []
Y1 = []
X2 = []
Y2 = []
X3 = []
Y3 = []
X4 = []
Y4 = []
for i in range(len(all_data1)-sequence_len):
    X1.append(all_data1[i:i+sequence_len])
    Y1.append(all_data1[i+sequence_len])
for i in range(len(all_data2)-sequence_len):
    X2.append(all_data2[i:i+sequence_len])
    Y2.append(all_data2[i+sequence_len])
for i in range(len(all_data3)-sequence_len):
    X3.append(all_data3[i:i+sequence_len])
    Y3.append(all_data3[i+sequence_len])
for i in range(len(all_data4)-sequence_len):
    X4.append(all_data4[i:i+sequence_len])
    Y4.append(all_data4[i+sequence_len])
X1 = np.array(X1)
Y1 = np.array(Y1)
X2 = np.array(X2)
Y2 = np.array(Y2)
X3 = np.array(X3)
Y3 = np.array(Y3)
X4 = np.array(X4)
Y4 = np.array(Y4)

X_train1, X_test1, Y_train1, Y_test1 = train_test_split(X1, Y1, test_size=0.05)
X_train2, X_test2, Y_train2, Y_test2 = train_test_split(X2, Y2, test_size=0.05)
X_train3, X_test3, Y_train3, Y_test3 = train_test_split(X3, Y3, test_size=0.05)
X_train4, X_test4, Y_train4, Y_test4 = train_test_split(X4, Y4, test_size=0.05)

def build_model(activation_name, ):
    model = Sequential()
    # model.add(LSTM(128, input_shape=(sequence_len,1),return_sequences=True))  #原来的
    # model.add(LSTM(128, input_shape=(sequence_len,1),return_sequences=True))
    # model.add(LSTM(64))
    # model.add(Dense(1,activation=activation_name))
    # optimizer =tf.optimizers.Adam(learning_rate=0.1) #原来的
    optimizer = tf.optimizers.Adam(learning_rate=0.05)
    # model.compile(loss='mean_squared_error', optimizer=optimizer, metrics=['mape'])
    # model.compile(loss='mean_squared_error', optimizer=optimizer, metrics=['mape'])

    model.add(keras.layers.LSTM(units=32, input_shape=(None, 1)))
    model.add(keras.layers.Dense(units=1))
    model.compile(optimizer='adam', loss='mean_squared_error')
    return model
lstm = build_model("sigmoid")
step = 250

X_train1.shape
X_train2.shape
X_train3.shape
X_train4.shape

history = lstm.fit(
    X_train1, Y_train1, epochs=50, batch_size = 32,verbose=0,validation_data = (X_test1, Y_test1)
    )
history = lstm.fit(
    X_train2, Y_train2, epochs=50, batch_size = 32,verbose=0,validation_data = (X_test2, Y_test2)
    )
history = lstm.fit(
    X_train3, Y_train3, epochs=50, batch_size = 32,verbose=0,validation_data = (X_test3, Y_test3)
    )
history = lstm.fit(
    X_train4, Y_train4, epochs=50, batch_size = 32,verbose=0,validation_data = (X_test4, Y_test4)
    )

Y_predict1 = lstm.predict(X_test1)
Y_predict2 = lstm.predict(X_test2)
Y_predict3 = lstm.predict(X_test3)
Y_predict4 = lstm.predict(X_test4)
Y_predict_real1 = stand_scaler.inverse_transform(Y_predict1.reshape(-1,1))
Y_predict_real2 = stand_scaler.inverse_transform(Y_predict2.reshape(-1,1))
Y_predict_real3 = stand_scaler.inverse_transform(Y_predict3.reshape(-1,1))
Y_predict_real4 = stand_scaler.inverse_transform(Y_predict4.reshape(-1,1))
Y_test_real1 = stand_scaler.inverse_transform(Y_test1.reshape(-1,1))
Y_test_real2 = stand_scaler.inverse_transform(Y_test2.reshape(-1,1))
Y_test_real3 = stand_scaler.inverse_transform(Y_test3.reshape(-1,1))
Y_test_real4 = stand_scaler.inverse_transform(Y_test4.reshape(-1,1))

#下面原本是在jupyter上显示图像的代码
# fig = plt.figure(figsize=(20, 2))
# plt.plot(Y_predict_real/(1024*1024))
# plt.plot(Y_test_real/(1024*1024))
# print(Y_predict_real/(1024*1024))
# print(Y_test_real/(1024*1024))
arr1 = Y_predict_real1.tolist()
arr11 = Y_test_real1.tolist()
arr2 = Y_predict_real2.tolist()
arr22 = Y_test_real2.tolist()
arr3 = Y_predict_real3.tolist()
arr33 = Y_test_real3.tolist()
arr4 = Y_predict_real4.tolist()
arr44 = Y_test_real4.tolist()

print("throughput:")
print(arr1)
print(arr11)
print("delay:")
print(arr2)
print(arr22)
print("jitter:")
print(arr3)
print(arr33)
print("loss:")
print(arr4)
print(arr44)


# print(arr11)
# print(type(arr1))
def MAPE(true, pred):
    diff = np.abs(np.array(true) - np.array(pred))
    return np.mean(diff / true)
def RMSE(predictions, targets):
    return np.sqrt(((predictions - targets) ** 2).mean())
print("throughput:")
print(f"根均方误差(RMSE)：{RMSE(Y_predict_real1/(1024*1024), Y_test_real1/(1024*1024))}")
print(f"平均绝对百分比误差(MAPE)：{MAPE(Y_predict1, Y_test1)}")
print("delay:")
print(f"根均方误差(RMSE)：{RMSE(Y_predict_real2, Y_test_real2)}")
print(f"平均绝对百分比误差(MAPE)：{MAPE(Y_predict2, Y_test2)}")
print("jitter:")
print(f"根均方误差(RMSE)：{RMSE(Y_predict_real3, Y_test_real3)}")
print(f"平均绝对百分比误差(MAPE)：{MAPE(Y_predict3, Y_test3)}")
print("loss:")
print(f"根均方误差(RMSE)：{RMSE(Y_predict_real4, Y_test_real4)}")
print(f"平均绝对百分比误差(MAPE)：{MAPE(Y_predict4, Y_test4)}")

T2 =time.process_time()
print('程序运行时间:%s毫秒' % ((T2 - T1)*1000))