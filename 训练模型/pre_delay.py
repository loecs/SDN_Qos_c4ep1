import pandas as pd
import numpy as np
import random

import pymysql
import tensorflow as tf
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from keras.models import Sequential
from keras.layers import Dense,LSTM

def delay():
    my_seed = 2017
    np.random.seed(my_seed)
    random.seed(my_seed)
    tf.random.set_seed(my_seed)

    # 导入数据测试
    df2 = 'DB_read.xlsx'
    data2 = pd.read_excel(df2)
    # data2.head(4)

    # 创建一个Series对象
    s = data2["delay"]
    # 将Series转换为ndarray
    arr = s.to_numpy()
    # 输出数组
    # print(arr)
    # 检查数据类型
    # type(arr)

    import matplotlib

    # all_data = np.fromfile("ec_data")
    all_data = arr
    type(all_data)

    stand_scaler = MinMaxScaler()
    all_data = stand_scaler.fit_transform(all_data.reshape(-1, 1))

    # sequence_len = 10 #原来的
    sequence_len = 60  # 最适合
    X = []
    Y = []
    for i in range(len(all_data) - sequence_len):
        X.append(all_data[i:i + sequence_len])
        Y.append(all_data[i + sequence_len])
    X = np.array(X)
    Y = np.array(Y)

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.05)

    def build_model(activation_name, ):
        model = Sequential()
        # model.add(LSTM(128, input_shape=(sequence_len,1),return_sequences=True))  #原来的
        # model.add(LSTM(128, input_shape=(sequence_len,1),return_sequences=True))
        # model.add(LSTM(64))
        # model.add(Dense(1,activation=activation_name))
        # optimizer =tf.optimizers.Adam(learning_rate=0.1) #原来的
        optimizer = tf.optimizers.Adam(learning_rate=0.05)
        # model.compile(loss='mean_squared_error', optimizer=optimizer, metrics=['mape'])
        model.add(keras.layers.LSTM(units=32, input_shape=(None, 1)))
        model.add(keras.layers.Dense(units=1))
        model.compile(optimizer='adam', loss='mean_squared_error')
        return model

    lstm = build_model("sigmoid")

    X_train.shape
    history = lstm.fit(
        X_train, Y_train, epochs=50, batch_size=32, verbose=0, validation_data=(X_test, Y_test)
    )

    Y_predict = lstm.predict(X_test)
    Y_predict.shape
    X_test.shape

    Y_predict_real = stand_scaler.inverse_transform(Y_predict.reshape(-1, 1))
    Y_test_real = stand_scaler.inverse_transform(Y_test.reshape(-1, 1))

    fig = plt.figure(figsize=(20, 2))
    plt.plot(Y_predict_real / (1024 * 1024))
    plt.plot(Y_test_real / (1024 * 1024))

    def MAPE(true, pred):
        diff = np.abs(np.array(true) - np.array(pred))
        return np.mean(diff / true)

    def RMSE(predictions, targets):
        return np.sqrt(((predictions - targets) ** 2).mean())

    print(f"根均方误差(RMSE)：{RMSE(Y_predict_real / (1024 * 1024), Y_test_real / (1024 * 1024))}")
    print(f"平均绝对百分比误差(MAPE)：{MAPE(Y_predict, Y_test)}")

    # N=int(input("请输入需要预测的数量"))
    N = 210

    current_seq = all_data[-sequence_len:]  # 获取最后一次的输入序列
    prediction = []  # 存放模型预测结果
    for i in range(N):
        # 对当前序列进行预测并加入到结果数组中
        predicted_value = lstm.predict(current_seq.reshape(1, sequence_len, 1))
        prediction.append(predicted_value[0, 0])
        # 将当前结果作为下一次的输入序列的一部分
        a = current_seq[1:]
        b = predicted_value
        current_seq = np.concatenate([a, b])

    prediction_real = stand_scaler.inverse_transform(np.array(prediction).reshape(-1, 1))
    # print("未来"+str(N)+"个时刻的预测值为：\n", prediction_real)  # 打印未来N个时刻的预测结果

    # 改数据格式
    prediction_real_change = []
    for j in prediction_real:
        prediction_real_change.extend(j)
    delay_vlues = prediction_real_change
    return delay_vlues


