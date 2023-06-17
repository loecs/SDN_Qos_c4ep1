# Common Setting for Networ awareness module.


DISCOVERY_PERIOD = 30  # For discovering topology.

MONITOR_PERIOD = 30  # For monitoring traffic

DELAY_DETECTING_PERIOD = 30  # For detecting link delay.

TOSHOW = False  # For showing information in terminal

MAX_CAPACITY = 281474976710655L  # Max capacity of link

SUBNET_PREFIX = '10.'

GATEWAY_IP = '10.0.0.15'

GATEWAY_KEY = (1, 5)

SAVE_SQL = False

SESSION_TOS = 16

STREAMING_TOS = 12

OPERATE_TOS = 8

DOWNLOAD_TOS = 4

SESSION_WEIGHT = {'BW': 0.15,'DELAY':0.4,'JITTER':0.3,'LOSS':0.15}

STREAMING_WEIGHT = {'BW': 0.5,'DELAY':0.1,'JITTER':0.1,'LOSS':0.3}

OPERATE_WEIGHT = {'BW': 0.2,'DELAY':0.4,'JITTER':0,'LOSS':0.4}

DOWNLOAD_WEIGHT = {'BW': 0.6,'DELAY':0,'JITTER':0,'LOSS':0.4}

SESSION_BW_MEASURE ={'A':0.2,'B':1,'c':6}

STREAMING_BW_MEASURE ={'A':0.004,'B':1,'c':14}

OPERATE_BW_MEASURE ={'A':0.25,'B':1,'c':6}

DOWNLOAD_BW_MEASURE ={'A':0.05,'B':1,'c':12}

SESSION_DELAY_MEASURE ={'y1':0.067,'B':0.04,'y2':0.016,'b1':-25,'b2':205,'b3':65,'c1':150,'c2':300,'delta':90}

STREAMING_DELAY_MEASURE ={'y1':0.004,'B':0.005,'y2':0.006,'b1':-25,'b2':625,'b3':75,'c1':200,'c2':1000,'delta':17.506}

OPERATE_DELAY_MEASURE ={'y1':0,'B':0.015,'y2':0,'b1':-45,'b2':1.35,'b3':60,'c1':0,'c2':0,'delta':0}

SESSION_JITTER_MEASURE ={'B':0.067,'b1':-30,'b2':50,'b3':70}

STREAMING_JITTER_MEASURE ={'B':0.005,'b1':-20,'b2':3,'b3':80}

SESSION_LOSS_MEASURE ={'B':3,'b1':882,'b2':200,'b3':50}

STREAMING_LOSS_MEASURE ={'B':12.5,'b1':250,'b2':50,'b3':20}

OPERATE_LOSS_MEASURE ={'B':1,'b1':100,'b2':50,'b3':1}

DOWNLOAD_LOSS_MEASURE ={'B':1,'b1':80,'b2':45,'b3':1}