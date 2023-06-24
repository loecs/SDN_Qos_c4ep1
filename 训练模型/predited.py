import pymysql

import pre_throughput
import pre_delay
import pre_jitter
import pre_loss
import DB_read

a = pre_throughput.throughput()
b = pre_delay.delay()
c = pre_jitter.jitter()
d = pre_loss.loss()

db = pymysql.connect(
    host='cloud.loecs.com',
    port=33060,
    user='c4bep1',
    password='c4bep1',
    database='c4bep1',
    charset='utf8'
)
cour = db.cursor()
for i in range(len(a)):
    sql_str = "insert into predicted(throughput,delay,jitter,loss) values (%s,%s,%s,%s)"
    cour.execute(sql_str,(a[i]/600,b[i],c[i],d[i]))
    db.commit()

cour.close()
db.close()