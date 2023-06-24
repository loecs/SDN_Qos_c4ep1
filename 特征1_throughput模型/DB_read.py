import pymysql
import xlwt
import pandas as pd

db = pymysql.connect(
    host='cloud.loecs.com',
    port=33060,
    user='c4bep1',
    password='c4bep1',
    database='c4bep1',
    charset='utf8'
)
cur = db.cursor()
print("successs!")
sql = "select * from link_stat;"
cur.execute(sql)
rows = cur.fetchall()

w = xlwt.Workbook(encoding='utf-8')
ws = w.add_sheet("link-stat", cell_overwrite_ok=True)
title = "id","record_time","link-id","throughput","delay","jitter","loss"
for index,t in enumerate(title):
    ws.write(0,index,t)
for i in range(len(rows)):
    row = rows[i]
    for j in range(len(row)):
        if row[j] != 0:
            item = row[j]
            ws.write(i + 1,j, item)
        else:
            int(row[j])==0
            item = int(row[j])
            ws.write(i + 1, j, item)


path = "DB_read.xlsx"
w.save(path)
db.close()
print("save finish!")
