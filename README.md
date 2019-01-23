### 1、本示例的 Python 版本为3.6
### 2、本仓库主要是为了提供签名方法（基于requests库的AuthBase），调用示例可以参考 运行实现
### 3、使用注意事项：
- 含有中文和空格的query, body在请求时需要对值进行urlencode处理，编码为utf-8.
- 参数参与签名时，必须使用原文签名，不能用urlencode后字符串的进行签名.所以请在签名之后再对query、body的值做urlencode.
- [签名文档](https://help.aliyun.com/document_detail/29475.html)

### 使用简单示例

```python
    import requests
    url = "http://*****.market.alicloudapi.com/*****"
    params = {"param": "param"}
    AppKey = "25xxxxxx"
    AppSecret = "fd838e3c8b016***************"
    AppCode = "736656a842d447*****************"

    r = requests.post(url, params=params, auth=AliyunMarketAuth(AppKey, AppSecret))
    s = requests.post(url, params=params, auth=AliyunMarketAuthLite(AppCode))

    print(r, s)
```
