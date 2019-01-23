#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# author: olutyo@gmail.org
#
# name: requests-auth-aliyunMarket
# desc: 该模块为阿里云云市场接入 apk_key apk_secret 的 requests 库的认证模块(包括简单认证 AppCode)
#
# license： MIT
# https://opensource.org/licenses/MIT



import time
import uuid
import hmac
import base64
import hashlib
from urllib.parse import unquote

from requests.auth import AuthBase
from requests.sessions import merge_setting
from requests.structures import CaseInsensitiveDict


class CurrentMoment(object):
    TIME_ZONE = "GMT"

    @property
    def iso_8061_date(self):
        FORMAT_ISO_8601 = "%Y-%m-%dT%H:%M:%SZ"
        return time.strftime(FORMAT_ISO_8601, time.gmtime())

    @property
    def rfc_2616_date(self):
        FORMAT_RFC_2616 = "%a, %d %b %Y %X {}".format(self.TIME_ZONE)
        return time.strftime(FORMAT_RFC_2616, time.gmtime())

    @property
    def timestamp(self):
        return str(int(time.time() * 1000))


class SignComposer(object):
    def get_md5_base64_str(self, strings=None):
        m = hashlib.md5()
        m.update(strings.encode('utf-8'))
        return base64.encodebytes(m.digest()).strip().decode()

    def get_sign(self, source, secret):
        source = source.encode("utf-8")
        secret = secret.encode("utf-8")
        h = hmac.new(secret, source, hashlib.sha256)
        signature = base64.encodebytes(h.digest()).strip().decode()
        return signature


class AliyunMarketAuth(AuthBase):
    def __init__(self, appKey, appSecret):
        self._appkey = appKey
        self._appSecret = appSecret
        self.moment = CurrentMoment()
        self.sign = SignComposer()
        self.tempHeader = None
        pass

    def __call__(self, r):
        r.headers = merge_setting(self.defaultHeaders(r), r.headers, dict_class=CaseInsensitiveDict)
        r.headers["X-Ca-Signature-Headers"], self.tempHeader = self._format_headers(r)
        r.headers["X-Ca-Signature"] = self.sign.get_sign(self.buildSignStr(r), self._appSecret)
        return r

    def defaultHeaders(self, r):
        headers = {
                "Date"             : r.headers.get("Date") or self.moment.rfc_2616_date,
                "Accept"           : "application/json" if r.headers.get("Accept") == "*/*" else r.headers["Accept"],
                "Content-Type"     : r.headers.get("Content-Type") or "application/x-www-form-urlencoded" if r.method == "POST" else None,
                "X-Ca-Request-Mode": r.headers.get("X-Ca-Request-Mode") or None,
                "X-Ca-Version"     : r.headers.get("X-Ca-Version") or "1",
                "X-Ca-Stage"       : r.headers.get("X-Ca-Stage") or "RELEASE",
                "X-Ca-Key"         : r.headers.get("X-Ca-Key") or self._appkey,
                "X-Ca-Timestamp"   : r.headers.get("X-Ca-Timestamp") or self.moment.timestamp,
                "X-Ca-Nonce"       : r.headers.get("X-Ca-Nonce") or str(uuid.uuid4())
                }
        return headers

    def buildSignStr(self, r):
        lf = "\n"
        string_to_sign = []

        string_to_sign.append(r.method)
        string_to_sign.append(lf)

        string_to_sign.append(r.headers["Accept"])
        string_to_sign.append(lf)

        if not ("application/x-www-form-urlencoded" in r.headers.get("Content-Type")):
            string_to_sign.append(self.sign.get_md5_base64_str(strings=r.body))
        string_to_sign.append(lf)

        string_to_sign.append(r.headers.get("Content-Type"))
        string_to_sign.append(lf)

        string_to_sign.append(r.headers["Date"])
        string_to_sign.append(lf)

        string_to_sign.append(self.tempHeader)

        string_to_sign.append(unquote(self._build_resource(r)))

        return ''.join(string_to_sign)

    def _format_headers(self, r):
        _headers_sign = ["X-Ca-Request-Mode", "X-Ca-Version", "X-Ca-Stage",
                         "X-Ca-Key", "X-Ca-Timestamp", "X-Ca-Nonce"]
        signHeader = []
        tempHeader = []
        headers_key_arry = [item for item in r.headers.keys()]
        headers_key_arry.sort()

        for item in headers_key_arry:
            if item in _headers_sign:
                signHeader.append(item)
                tempHeader.append("{item}:{value}\n".format(item=item, value=r.headers.get(item)))

        return ','.join(signHeader), ''.join(tempHeader)

    def _build_resource(self, r):
        body = {}
        resource = []
        uri = ""

        if "?" in r.path_url:
            uri, query_str = r.path_url.split("?")
            if query_str:
                query_str_array = query_str.split("&")
                for query in query_str_array:
                    try:
                        k, v = query.split("=")
                    except ValueError:
                        k = query
                        v = None
                    if k not in body:
                        body[k] = v
        else:
            uri = r.path_url

        if r.body:
            if r.headers.get("Content-Type") == "application/x-www-form-urlencoded":
                query_str_array = r.body.split("&")
                for query in query_str_array:
                    try:
                        k, v = query.split("=")
                    except ValueError:
                        k = query
                        v = None
                    if k not in body:
                        body[k] = v

        if "?" in r.path_url or r.body:
            resource.append("?")

            param_list = [param for param in body.keys()]
            param_list.sort()
            first = True
            for key in param_list:
                if not first:
                    resource.append("&")
                first = False

                if body[key]:
                    resource.append("{key}={value}".format(key=key, value=body[key]))
                else:
                    resource.append(key)

        return uri + ''.join(str(x) for x in resource)


class AliyunMarketAuthLite(AuthBase):
    def __init__(self, AppCode):
        self._appCode = AppCode
    def __call__(self, r):
        r.headers["Authorization"] = "APPCODE " + self._appCode
        return r

if __name__ == "__main__":
    import requests
    url = "http://*****.market.alicloudapi.com/*****"
    params = {"param": "param"}
    AppKey = "25xxxxxx"
    AppSecret = "fd838e3c8b016***************"
    AppCode = "736656a842d447*****************"

    r = requests.post(url, params=params, auth=AliyunMarketAuth(AppKey, AppSecret))
    s = requests.post(url, params=params, auth=AliyunMarketAuthLite(AppCode))

    print(r, s)
