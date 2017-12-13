# -*- coding: utf-8 -*-
# @Author  : oldsyang

import hashlib
import string
import requests
import json
import random
import time
import base64
import struct
from M2Crypto import BIO, RSA as MRSA

from django.utils.encoding import smart_str
from django.conf import settings
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256, MD5, SHA
from Crypto.Cipher import DES, DES3


class WeixinException(Exception):
    def __init__(self, msg):
        super(WeixinException, self).__init__(msg)


class JdPay(object):
    def __init__(self, config):
        self.MERCHANT = getattr(config, "MERCHANT")
        self.MERCHANT_DESKEY = getattr(config, "MERCHANT_DESKEY")
        self.MERCHANT_MD5KEY = getattr(config, "MERCHANT_MD5KEY")
        self.MERCHANT_RSA_PRI_KEY = getattr(config, "MERCHANT_RSA_PRI_KEY")
        self.MERCHANT_RSA_PUB_KEY = getattr(config, "MERCHANT_RSA_PUB_KEY")
        self.ASYN_NOTIFY_URL = getattr(config, "ASYN_NOTIFY_URL")
        self.REDIRECT_URL = getattr(config, "REDIRECT_URL")
        self.PAY_URL = getattr(config, "PAY_URL")

    @staticmethod
    def get_nonce_str(length=32):
        '''

        Args:
            length(int): 随机数的长度

        Returns:
            返回length长度的随机字符串

        '''
        char = string.ascii_letters + string.digits
        return "".join(random.choice(char) for _ in range(length))

    @staticmethod
    def get_sign_str(params, is_compatible=False):
        """
        生成签名的字符串
        Args:
            params: 签名的字典数据
            is_compatible: 是否是兼容模式（对字典中value值为空的也签名）

        Returns:
            返回签名
        """

        raw = [(k, params[k]) for k in sorted(params.keys())]
        if is_compatible:
            order_str = "&".join("=".join(kv) for kv in raw)
        else:
            order_str = "&".join("=".join(kv) for kv in raw if kv[1])

        return order_str

    @staticmethod
    def __sha256(string):
        sha_hash = SHA256.new(string)
        hex_hash = sha_hash.hexdigest()
        return hex_hash

    def encrypt_info(self, params_dict, extra_encryption_fields=None):
        """
        加密敏感的数据
        Args:
            params_dict(dict): 要加密的数据源
            extra_encryption_fields(tuple): 不加密的key

        Returns:

        """

        # 字典中不需加密的数据

        extra_encryption_fields = extra_encryption_fields or ("version", "merchant", "sign")
        for field in params_dict:
            if field not in extra_encryption_fields:
                params_dict[field] = self.encode_des(params_dict[field], self.MERCHANT_DESKEY)

    def to_form(self, params, action_url):
        """
        将字典数据转化为form字符串
        Args:
            params(dict): 要拼接的数据源
            action_url(str): form表单的action

        Returns:

        """
        # 拼接参数的xml字符串
        form_str = '<form method="post" action="{0}" id="batchForm">'.format(action_url)
        for key, value in params.items():
            input_str = ' <input name="{0}" type="hidden" id="{1}" value="{2}" /><br/>'.format(key, key, value)
            form_str = "".join([form_str, input_str])
        form_str = '%s</form>' % form_str
        return form_str

    def sign(self, prestr):
        """
        生成签名
        Args:
            prestr(str): 生成签名的原字符串

        Returns:
            返回生成好的签名           
        """
        key = MRSA.load_key(self.MERCHANT_RSA_PRI_KEY)
        signature = key.private_encrypt(self.__sha256(prestr), MRSA.pkcs1_padding)
        sign = base64.b64encode(signature)
        return sign



    @staticmethod
    def des_pad(data):
        e = len(data)
        x = (e + 4) % 8
        y = 0 if x == 0 else 8 - x
        sizeByte = struct.pack('>I', e)
        resultByte = range(len(sizeByte) + e + y)
        resultByte[0:4] = sizeByte
        resultByte[4:4 + e] = data
        for i in range(0, y):
            resultByte[e + 4 + i] = "\x00"
        resultstr = ''.join(resultByte)
        return resultstr

    @staticmethod
    def encode_des(to_encode_str, des_key):
        """
        DES3加密数据
        Args:
            to_encode_str(str): 要被加密的原字符串，这里的字符串需要被des_pad一下
            des_key(str): 加密的key
        Returns:

        """

        key = base64.b64decode(des_key)
        des3 = DES3.new(key, DES3.MODE_ECB)
        return des3.encrypt(JdPay.des_pad(to_encode_str)).encode('hex_codec')

    @staticmethod
    def un_des_pad(data):
        resultByte = data[0:4]
        e = struct.unpack('>I', resultByte)[0]
        x = (e + 4) % 8
        y = 0 if x == 0 else 8 - x
        return data[4:] if y == 0 else data[4:-y]

    @staticmethod
    def decode_des(to_decode_str, des_key):
        """
        解密数据
        Args:
            to_decode_str(str): 要解密的原字符串
            des_key(str): 解密的key

        Returns:

        """

        key = base64.b64decode(des_key)
        des3 = DES3.new(key, DES3.MODE_ECB)
        param = to_decode_str.decode('hex_codec')
        param = des3.decrypt(param)
        return JdPay.un_des_pad(param)

    def create_order(self, **kwargs):
        '''
        统一下单
        Args:
            kwargs(dict):
            version(str): 当前固定填写：V2.0
            merchant(str): 、商户号（由京东分配）
            tradeNum(str): 	商户唯一交易流水号。格式：字母&数字
            tradeName(str): 商户订单的标题/商品名称/关键字等
            tradeTime(str): 订单生成时间。格式：“yyyyMMddHHmmss”
            amount(long): 商户订单的资金总额。单位：分，大于0
            orderType(str): 固定值：0或者1 （0：实物，1：虚拟）
            currency(str): 货币类型，固定填CNY
            callbackUrl(str): 支付成功后跳转的URL
            notifyUrl(str): 支付完成后，京东异步通知商户服务相关支付结果。必须是外网可访问的url。
            userId(str): 商户平台用户的唯一账号。注：用户账号是商户端系统的用户唯一账号。

        Returns:
            返回二维码的content

        '''

        # if "version" not in kwargs:
        #     raise WeixinException("缺少在线支付必填参数version")
        # if "merchant" not in kwargs:
        #     raise WeixinException("缺少在线支付必填参数merchant")
        if "tradeNum" not in kwargs:
            raise WeixinException("缺少在线支付必填参数tradeNum")
        if "tradeName" not in kwargs:
            raise WeixinException("缺少在线支付必填参数tradeName")
        if "tradeTime" not in kwargs:
            raise WeixinException("缺少在线支付必填参数tradeTime")
        if "amount" not in kwargs:
            raise WeixinException("缺少在线支付必填参数amount")
        if "orderType" not in kwargs:
            raise WeixinException("缺少在线支付必填参数orderType")
        if "currency" not in kwargs:
            raise WeixinException("缺少在线支付必填参数currency")
        if not self.ASYN_NOTIFY_URL:
            raise WeixinException("缺少在线支付必填参数notifyUrl")
        if not self.REDIRECT_URL:
            raise WeixinException("缺少在线支付必填参数callbackUrl")
        if "userId" not in kwargs:
            raise WeixinException("缺少在线支付必填参数userId")

        if not self.PAY_URL:
            raise WeixinException("缺少在线支付的url")

        params = {
            "version": "V2.0",
            "currency": "CNY",

            "merchant": self.MERCHANT,
            "callbackUrl": self.REDIRECT_URL,
            "notifyUrl": self.ASYN_NOTIFY_URL,

            "tradeNum": kwargs.get("tradeNum"),
            "tradeName": kwargs.get("tradeName"),
            "tradeTime": kwargs.get("tradeTime"),
            "amount": kwargs.get("amount"),
            "orderType": kwargs.get("orderType"),
            "userId": kwargs.get("userId")
        }

        sign_str = self.sign(self.get_sign_str(params))
        self.encrypt_info(params)
        params["sign"] = sign_str
        # 转为form字符串
        form_str = self.to_form(params, self.PAY_URL)

        print("form_str:", form_str)

        # 测试
        res = requests.post(self.PAY_URL, data=params)
        return res.text

        return form_str



        # res_content_dict = self.__option_params_return_dict(self.ORDER_URL, params)
        # return res_content_dict, self.get_qrcode(res_content_dict, "code_url")

# 京东伪代码
# def des_pad(data):
#     e = len(data)
#     x = (e + 4) % 8
#     y = 0 if x == 0 else 8 - x
#     sizeByte = struct.pack('>I', e)
#     resultByte = range(len(sizeByte) + e + y)
#     resultByte[0:4] = sizeByte
#     resultByte[4:4 + e] = data
#     for i in range(0, y):
#         resultByte[e + 4 + i] = "\x00"
#     resultstr = ''.join(resultByte)
#     return resultstr
#
# def un_des_pad(data):
#     resultByte = data[0:4]
#     e = struct.unpack('>I', resultByte)[0]
#     x = (e + 4) % 8
#     y = 0 if x == 0 else 8 - x
#     return data[4:] if y == 0 else data[4:-y]
#
# def encode_des(param):
#     key = create_key(Config.JDPAY_MERCHANT_DESKEY)
#     des3 = DES3.new(key, DES3.MODE_ECB)
#     param = des3.encrypt(des_pad(param)).encode('hex_codec')
#     return param
#
#
# def decode_des(param):
#     key = create_key(Config.JDPAY_MERCHANT_DESKEY)
#     des3 = DES3.new(key, DES3.MODE_ECB)
#     param = param.decode('hex_codec')
#     param = des3.decrypt(param)
#     return un_des_pad(param)
#
# # 生成签名结果
# def build_mysign(prestr):
#     key = RSA.load_key(Config.JDPAY_PRIVATE_KEY)
#     signature = key.private_encrypt(SHA.new(prestr).hexdigest(), RSA.pkcs1_padding)
#     # base64 编码，转换为unicode表示并移除回车
#     sign = base64.encodestring(signature).decode("utf8").replace("\n", "")
#     return sign
#
# def notify_verify(xml_data):
#     xml_str = decode_des(base64.standard_b64decode(xml_data))
#     sign_begin = xml_str.find('<sign>')
#     sign_end = xml_str.find('</sign>')
#     if sign_begin>0 and sign_end>0:
#         sign = xml_str[sign_begin+6:sign_end]
#         xml_new_str = xml_str[:sign_begin] + xml_str[sign_end+7:]
#         if verify_mysign(sign, xml_new_str):
#             return xml_new_str
#     return False
#
# def verify_mysign(sign, xml_str):
#     xml_sha_str = SHA.new(xml_str).hexdigest()
#     key = RSA.load_pub_key(Config.JDPAY_PUBLIC_KEY)
#     signature = key.public_decrypt(base64.standard_b64decode(sign),
#                                    RSA.pkcs1_padding)
#     return signature == xml_sha_str
