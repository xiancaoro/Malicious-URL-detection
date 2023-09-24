# 安装一些需要的包

# pip install whois
# pip install tldextract
# pip install tldextract

# 引入我们需要的包（特征提取）
import os
import sys
import re
import matplotlib
import pandas as pd
import numpy as np
from os.path import splitext
import ipaddress as ip
import tldextract
import whois
import datetime
from urllib.parse import urlparse

df1 = pd.read_csv("//home/aistudio/data/data54433/phishing_verified_online.csv")
df2 = pd.read_csv("/home/aistudio/data/data170812/benign-URL-dmoz-datasets.zip")

# 打标签
df1.insert(df1.shape[1], 'label', 1)
df2.insert(df2.shape[1], 'label', 0)

col_names = ["url","lable"]

df1 = df1.iloc[:,[1,8]]
df2 = df2.iloc[:,[1,3]]
df2 = df2[0:40000]

df2.columns = col_names

# 拼接两个dataframe
df = pd.concat([df1,df2],join='inner')
# 随机取样
df = df.sample(frac=1).reset_index(drop = True)
# 展示
df.head()


# 可疑的TLD与域
Suspicious_TLD=['zip','cricket','link','work','party','gq','kim','country','science','tk']
Suspicious_Domain=['luckytime.co.kr','mattfoll.eu.interia.pl','trafficholder.com','dl.baixaki.com.br','bembed.redtube.comr','tags.expo9.exponential.com','deepspacer.com','funad.co.kr','trafficconverter.biz']

# 统计URL中的‘.’
def countdots(url):  
    return url.count('.')

# 统计url中的分隔符
# 比如 ':' , '_' , '?' , '=' , '&'
def countdelim(url):
    count = 0
    delim = [':','_','?','=','&']
    for each in url:
        if each in delim:
            count = count + 1
    return count

# 验证IP地址是否为主机名
import ipaddress as ip

def isip(uri):
    try:
        if ip.ip_address(uri):
            return 1
    except:
        return 0

# 检查连字符'-'
def isPresentHyphen(url):
    return url.count('-')

# 检查符号'@'
def isPresentAt(url):
    return url.count('@')

# 检查符号'//'
def isPresentDSlash(url):
    return url.count('//')

# 统计符号'/'的数量
def countSubDir(url):
    return url.count('/')

# URL中是否有文件名
def get_ext(url):
    root, ext = splitext(url)
    return ext

# 统计子域名
def countSubDomain(subdomain):
    if not subdomain:
        return 0
    else:
        return len(subdomain.split('.'))

# 统计间隔符
def countQueries(query):
    if not query:
        return 0
    else:
        return len(query.split('&'))

featureSet = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at',\
'presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD',\
'presence of suspicious domain','label'))

featureSet.head()

from urllib.parse import urlparse
import tldextract

def getFeatures(url, label): 
    result = []
    url = str(url)
    
    # 在特征集里加入URL
    result.append(url)
    
    # 解析URL，提取域信息
    path = urlparse(url)
    ext = tldextract.extract(url)
    
    # 计算子域名中点的数量  
    result.append(countdots(ext.subdomain))
    
    # 检查URL中的连字符  
    result.append(isPresentHyphen(path.netloc))
    
    # 检查URL的长度 
    result.append(len(url))
    
    # 检查URL中'@'  
    result.append(isPresentAt(path.netloc))
    
    # 检查URL中的'//'  
    result.append(isPresentDSlash(path.path))
    
    #Count number of subdir    
    result.append(countSubDir(path.path))
    
    # 子域名的数量   
    result.append(countSubDomain(ext.subdomain))
    
    # 子域名的长度    
    result.append(len(path.netloc))
    
    # 计算URL中'&'的数量   
    result.append(len(path.query))
    
    # URL是不是IP地址   
    result.append(isip(ext.domain))
    
    # 可疑的TLD
    result.append(1 if ext.suffix in Suspicious_TLD else 0)
    
    # 可疑的域名
    result.append(1 if '.'.join(ext[1:]) in Suspicious_Domain else 0 )

    result.append(str(label))
    return result


for i in range(len(df)):
    features = getFeatures(df["url"].loc[i], df["lable"].loc[i])    
    featureSet.loc[i] = features      


import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import pickle as pkl
# from __future__ import division


# 可以查看图形来判断特征的选取是否理想 这里选取URL长度进行查看
sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['len of url'],color='blue',label='Benign URLs')
sns.distplot(featureSet[featureSet['label']=='1']['len of url'],color='red',label='Phishing URLs')
sns.plt.title('Url Length Distribution')
plt.legend(loc='upper right')
plt.xlabel('Length of URL')

sns.plt.show()


import sklearn.ensemble as ek
from sklearn import model_selection
from sklearn import tree, linear_model
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn import preprocessing
from sklearn import svm
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier  # 导入sklearn库的RandomForestClassifier函数

featureSet.groupby(featureSet['label']).size()
x = featureSet.drop(['url','label'],axis=1).values
y = featureSet['label'].values

# 使用随机森林
model = ek.RandomForestClassifier(n_estimators=50)
x_train, x_test, y_train, y_test = model_selection.train_test_split( 
                                                                x,  
                                                                y, 
                                                                random_state = 1,
                                                                test_size = 0.3)

model.fit(x_train,y_train)
score = model.score(x_test,y_test)
print ("%s : %s " %("RandomForest",score))


#查看其余指标
from sklearn import metrics

expected = y_test  # 测试样本的期望输出
predicted = model.predict(x_test)  # 测试样本预测

print(metrics.classification_report(expected, predicted))  # 输出结果，精确度、召回率、f-1分数


# 可以进行测试
result = pd.DataFrame(columns=('url','no of dots','presence of hyphen','len of url','presence of at',\
'presence of double slash','no of subdir','no of subdomain','len of domain','no of queries','is IP','presence of Suspicious_TLD',\
'presence of suspicious domain','label'))

results = getFeatures('[这里输入你想测试的链接]','')
result.loc[0] = results
result = result.drop(['url','label'],axis=1).values
print(model.predict(result))