### 一、题目要求 

从AIStudio课程作业中选择《恶意网址检测》恶意和正常URL链接数据进行 研究(特征选择、算法选择)，并编写代码构建模型，最终满足如下需求： 

- [x] 打印出模型的准确率和召回率 
- [x] 代码可以根据输入的URL自动判定其安全性



### 二、技术要点 

#### 1、区分正常与恶意网址差异 

##### 表层特征： 

- [x] 字符/数字组成元素 
- [x] 整体字符的长度 
- [x] 各组成部分是否都存在 
- [x] 网址文件后缀语义(静态/动态、可执行文件 ...) 

##### 深层特征： 

- [ ] 分词、单词数量 
- [ ] 信息熵(字符复杂度) 
- [ ] 单词语义及前后关系、单词是否常用词 
- [ ] 域名后缀，代表含义



### 三、代码讲解

#### 1、数据预处理

##### ①取样

```python
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
```





#### 2、特征分析

##### ①通过查阅一些资料来分析分析可疑的域名与TLD

```python
# 可疑的TLD与域
Suspicious_TLD=['zip','cricket','link','work','party','gq','kim','country','science','tk']

Suspicious_Domain=['luckytime.co.kr','mattfoll.eu.interia.pl','trafficholder.com','dl.baixaki.com.br','bembed.redtube.comr','tags.expo9.exponential.com','deepspacer.com','funad.co.kr','trafficconverter.biz']
```



##### ②从URL中抽取特征

```python
# 统计URL中的‘.’
def countdots(url):  
    return url.count('.')
```

统计URL中的分隔符

```python
# 统计url中的分隔符
# 比如 ':' , '_' , '?' , '=' , '&'
def countdelim(url):
    count = 0
    delim = [':','_','?','=','&']
    for each in url:
        if each in delim:
            count = count + 1
    return count
```

当使用IP地址替换URL中的域名时，一般都有着安全风险

```python
# 验证IP地址是否为主机名
import ipaddress as ip

def isip(uri):
    try:
        if ip.ip_address(uri):
            return 1
    except:
        return 0
```

检查URL中的连字符

```python
# 检查连字符'-'
def isPresentHyphen(url):
    return url.count('-')

# 统计符号'/'的数量
def countSubDir(url):
    return url.count('/')
```

检查URL中的' @ '，@后一般都指向另一个网站

```python
# 检查符号'@'
def isPresentAt(url):
    return url.count('@')
```

检查URL中的' // '，//一般与网页重定向有关

```python
# 检查符号'//'
def isPresentDSlash(url):
    return url.count('//')
```

统计URL中' / '的数量

```python
def countSubDir(url):
	return url.count('/')
```

统计URL中的' & '，&为不同参数间的间隔符

```python
def countQueries(query):
    if not query:
        return 0
    else:
        return len(query.split('&'))
```

检查URL中是否有文件名

```python
def get_ext(url):
	root, ext = splitext(url)
	return ext
```

检查URL中的子域名

```python
def countSubDomain(subdomain):
    if not subdomain:
        return 0
    else:
        return len(subdomain.split('.'))
```



##### ③输出特征集

（省去取特征集的过程）

```python
for i in range(len(df)):
    features = getFeatures(df["url"].loc[i], df["lable"].loc[i])    
    featureSet.loc[i] = features  
    
featureSet.head()
```




### 三、可视化数据

##### ①选取部分特征进行可视化分析

```python
sns.set(style="darkgrid")
sns.distplot(featureSet[featureSet['label']=='0']['len of
url'], color='green', label='Benign URLs')
sns.distplot(featureSet[featureSet['label']=='1']['len of
url'], color='red', label='Phishing URLs')
sns.plt.title('Url Length Distribution')
plt.legend(loc='upper right')
plt.xlabel('Length of URL')
sns.plt.show()
```


后续操作可以依据这个



### 四、训练

##### ①划分训练指标

```python
x = featureSet.drop(['url','label'],axis=1).values
y = featureSet['label'].values
```

##### ②选取训练模型

```python
# 随机森林
model = ek.RandomForestClassifier(n_estimators=50)
```

##### ③数据分割

```python
x_train, x_test, y_train, y_test = model_selection.train_test_split( 
                                                        x,  
                                                        y, 
                                                        random_state = 1,
                                                        test_size = 0.3)
```

##### ④输出结果

```python
model.fit(x_train,y_train)
score = model.score(x_test,y_test)
print ("%s : %s " %("RandomForest",score))
```


##### ⑤其余指标

```python
from sklearn import metrics
# 测试样本的期望输出
expected = y_test
# 测试样本预测
predicted = model.predict(x_test)
print(metrics.classification_report(expected, predicted))
# 输出结果，精确度、召回率、f-1分数
```



### 五、检测

代码中剩余部分就是了（在master分支中），没什么技术含量就不多赘述了
