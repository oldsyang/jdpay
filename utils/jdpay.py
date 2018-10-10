# -*- coding: utf-8 -*-
# @Author  : oldsyang

import base64
import random
import string
import struct

import requests
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256
from M2Crypto import RSA as MRSA
from django.conf import settings


class JdException(Exception):
    def __init__(self, msg):
        super(JdException, self).__init__(msg)


class ToolsClass(object):
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
        return des3.encrypt(ToolsClass.des_pad(to_encode_str)).encode('hex_codec')

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
        param = to_decode_str.decode("hex_codec") if to_decode_str is bytes else base64.b64decode(to_decode_str).decode(
            "hex_codec")
        param = des3.decrypt(param)
        return ToolsClass.un_des_pad(param)

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
    def sha256(string):
        sha_hash = SHA256.new(string)
        hex_hash = sha_hash.hexdigest()
        return hex_hash


class JdPay(ToolsClass):
    def __init__(self, config):
        self.MERCHANT = getattr(config, "MERCHANT")
        self.MERCHANT_DESKEY = getattr(config, "MERCHANT_DESKEY")
        self.MERCHANT_MD5KEY = getattr(config, "MERCHANT_MD5KEY")
        self.MERCHANT_RSA_PRI_KEY = getattr(config, "MERCHANT_RSA_PRI_KEY")
        self.MERCHANT_RSA_PUB_KEY = getattr(config, "MERCHANT_RSA_PUB_KEY")
        self.ASYN_NOTIFY_URL = getattr(config, "ASYN_NOTIFY_URL")
        self.REDIRECT_URL = getattr(config, "REDIRECT_URL")
        self.PAY_URL = getattr(config, "PAY_URL")
        self.REFUND_URL = getattr(config, "REFUND_URL")
        self.REVOKE_URL = getattr(config, "REVOKE_URL")

        self.REFUND_NOTIFY_URL = getattr(config, "REFUND_NOTIFY_URL")

    @classmethod
    def notify_verify(cls, xml_data, deskey, jd_public_key):
        '''
        解密数据，并验证签名
        Args:
            xml_data: 
            deskey: 
            jd_public_key: 

        Returns:
            返回解密后的xml的字符串
        '''
        sign_begin = xml_data.find('<encrypt>')
        sign_end = xml_data.find('</encrypt>')
        encrypt_str = xml_data[sign_begin + 9:sign_end]
        xml_str = JdPay.decode_des(encrypt_str, deskey)

        sign_begin = xml_str.find('<sign>')
        sign_end = xml_str.find('</sign>')
        if sign_begin > 0 and sign_end > 0:
            sign = xml_str[sign_begin + 6:sign_end]
            xml_new_str = xml_str[:sign_begin] + xml_str[sign_end + 7:]
            if cls.verify_mysign(sign, xml_new_str, jd_public_key):
                return xml_new_str
        return False

    @classmethod
    def verify_mysign(cls, sign, xml_str, jd_public_key):
        """
        验证签名
        Args:
            sign: 签名
            xml_str: 去除签名后的xml字符串
            jd_public_key: 用于验证的key

        Returns:

        """
        xml_sha_str = SHA256.new(xml_str).hexdigest()
        key = MRSA.load_pub_key(jd_public_key)
        signature = key.public_decrypt(base64.standard_b64decode(sign),
                                       MRSA.pkcs1_padding)
        return signature == xml_sha_str

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

    def to_xml(self, params):
        xml_str = '<?xml version=\"1.0\" encoding=\"UTF-8\"?><jdpay>'
        for key, value in params.items():
            input_str = '<{0}>{1}</{0}>'.format(key, value)
            xml_str = "".join([xml_str, input_str])
        xml_str = '%s</jdpay>' % xml_str
        return xml_str

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
        form_str = '{}{}</form>'.format(form_str, "<input class='btn btn-default' type='submit' value={} />")
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
        signature = key.private_encrypt(self.sha256(prestr), MRSA.pkcs1_padding)
        sign = base64.b64encode(signature)
        return sign

    def unsign(self, prestr):
        pubkey = """-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKE5N2xm3NIrXON8Zj19GNtLZ8
xwEQ6uDIyrS3S03UhgBJMkGl4msfq4Xuxv6XUAN7oU1XhV3/xtabr9rXto4Ke3d6
WwNbxwXnK5LSgsQc1BhT5NcXHXpGBdt7P8NMez5qGieOKqHGvT0qvjyYnYA29a8Z
4wzNR7vAVHp36uD5RwIDAQAB
-----END RSA PUBLIC KEY-----"""
        rsa_pub = MRSA.load_pub_key(self.MERCHANT_RSA_PUB_KEY)
        unsign_str = rsa_pub.public_decrypt(base64.standard_b64decode(prestr), MRSA.pkcs1_padding)  # 解密
        unsign_str = base64.b64encode(unsign_str)
        return unsign_str

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
        self.param_dict = ["tradeNum", "tradeName", "tradeTime", "amount", "orderType", "currency", "userId"]
        for each in self.param_dict:
            if each not in kwargs:
                raise JdException("缺少在线支付必填参数{}".format(each))

        if not self.ASYN_NOTIFY_URL:
            raise JdException("缺少在线支付必填参数notifyUrl")
        if not self.REDIRECT_URL:
            raise JdException("缺少在线支付必填参数callbackUrl")
        if not self.PAY_URL:
            raise JdException("缺少在线支付的url")

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

        # 签名：http://payapi.jd.com/docList.html?methodName=2
        sign_str = self.sign(self.get_sign_str(params))

        # 对每个字段进行加密：http://payapi.jd.com/docList.html?methodName=2
        self.encrypt_info(params)

        # 添加sign
        params["sign"] = sign_str

        # 测试代码+++++++++++++++++++
        # 转为form字符串
        form_str = self.to_form(params, self.PAY_URL)
        print("form_str:", form_str)
        # res = requests.post(self.PAY_URL, data=params)
        # 测试代码结束————————
        return form_str, params

    def revoke(self, **kwargs):
        """

        Args:
            **kwargs: 
            tradeNum(str): 1. 不支持批量退款，格式为数字或字母，用于标识本次退款请求；2.支持多次部分退款，退款总金额需小于实收总金额，每次退款交易流水号需不同
            oTradeNum(str): 格式为数字或字母的字符串，其值为需要退款的原支付的交易流水号。
            tradeTime(str): 订单生成时间。格式：“yyyyMMddHHmmss”
        Returns:

        """
        if "amount" not in kwargs:
            raise JdException("缺少撤销申请必填参数amount")
        if "oTradeNum" not in kwargs:
            raise JdException("缺少撤销申请必填参数oTradeNum")
        if "tradeTime" not in kwargs:
            raise JdException("缺少撤销申请必填参数tradeTime")

        if not self.REVOKE_URL:
            raise JdException("缺少撤销申请的url")

        params = {
            "version": "V2.0",
            "currency": "CNY",
            "amount": kwargs.get("amount"),

            "merchant": self.MERCHANT,

            "tradeNum": kwargs.get("tradeNum"),
            "tradeTime": kwargs.get("tradeTime"),
            "oTradeNum": kwargs.get("oTradeNum"),
        }

        return self._option_data(params, self.REVOKE_URL)

    def _option_data(self, params, to_url):
        """
        签名，加密并发送报文
        Args:
            params: 
            to_url: 

        Returns:
        解密并验证请求返回的数据，成功则返回没有sign的xml字符串，否则返回None
        """
        # 1.拿到即将用于签名的明文的xml字符串（不含sign）
        xml_str = self.to_xml(params)

        # 签名，xml格式的签名和form表单提交的签名规则是不一样的，一定要看清楚（http://payapi.jd.com/docList.html?methodName=2）
        sign_str = self.sign(xml_str)

        # self.encrypt_info(params)
        params["sign"] = sign_str

        # 2.拿到即将用于加密的明文的xml字符串（含sign）
        encode_xml_str = self.to_xml(params)

        # 加密字符串，xml格式的加密和form表单提交的加密规则是不一样的，一定要看清楚（http://payapi.jd.com/docList.html?methodName=2）
        encode_str = self.encode_des(encode_xml_str, self.MERCHANT_DESKEY)

        encrypt_prams = {
            "encrypt": base64.b64encode(encode_str),
            "version": "V2.0",
            "merchant": self.MERCHANT
        }

        # 3.拿到即将用于发送的明文的xml字符串（含加密的信息）
        xml_str_with_encrypt = self.to_xml(encrypt_prams)

        # 测试代码开始+++++++++++++++++++
        # xml_str_with_encrypt = '<?xml version="1.0" encoding="UTF-8"?><jdpay><encrypt>YjkzZGY0NTZkNjFhZDg0MThjNjc0YmY1ZWJlY2QyODU0YTc5NmQ3ZWQxMWU1NzE3MWQ0OTUwOGI5NzllYmE4ZjM1YzRiZjlmYWE1M2ZiYjVjYTg5YjA4NTdhMjg3NTBhMWNkY2Q4MzAzYzg2NDM4NGJhYzA0YWE4ZTQwNWNiZTQ0MmM0NWIwYWJjMDA0MzcyZDM3ODZlNGE4MDUxODk3NjAzNDQ0ZjVkZDAzMjVkMjM5N2I0ZTRkNzk1Y2JlMmUwNmZkYTUzZDQ1YTY3MjJlODZmYzU4MmRiYjA0OWJmNjFlZjFmNmVlMGEzYTQ4ZGFkMWQ4ZWQ0NGJlZTlkOWVjMzQ2YWQ0YWM4YTVmZGI3MjEwOTVhNGYzZDhiMGFjYmU3ZDIxNjkwMmZkOTQ3ZjQ1YmRmOTBmMzQwZjg1ZGFiOWM5OWI3MTUxMjU4ZTQ2Y2RiMjk0MWZlYmYzZGJjOWU2YzM5NTJlNjE5NzNlMDkxMzM2YTEyMzA4YzlhZGU5YmVhZjU5OTQyZTNjOWZlMjhlNjgxZTAwZmQxYTA0Mjg3OTVmZjc0M2Y0MjljMWE5NWNmODdjYmNkNWFhNzE1ZjM5OTY1NWYyYzUzNGM3ODBiMDgzNWI5ZDkyYzQ3OTU4OTc2Nzk4ZTc1MTcwYTA2ODk3ZjhkODgxODdjZTcyZjUyYjAzNTgyYzJiZTE2NGQzMTdjOTliZDEzMjc5ODE0NTNlYzY5NGM2ZjJkYjNhMzU1MjRkMjkxYjhjY2U1NmRjMmJhOGRhYmVkYTQ0ZTdhNGNhNDkxZDAzZjcwOWUwM2RmOWQ2NmNhOTYyNDdiNTBhODE5NzQxM2ZjOWFlN2U3YTNlYzM5ZTI5OTBkZDczNzQ5MjhjM2UxMjhkYWJhMGM0NWY2YWMwNzhmYzY2ZTc2MzA0ZjAwYjQ1MDgxY2Y5NTVhYTg0MjhiMmM4YjY1NGU1MGE3MTdhZjg4MjA3ZGFjMzBlNWUwMGFhNDBhMzBkODYwNmU3ZjU1OTRhNDA5NTljZDRjZWE4NmI3MDgyMzE4NzNlMzMxY2I0NGFkOTg1YjRmMDY1Y2JmNWQzOGZlZWY2YjY1ODEzM2UzY2UzNmU0NzNkZWUzOTY1MGYxNzQ3NzEyOWNlNDZjNGYyYWY1NjlhODc2ODcxYzkzYWE3NDk4ZGQ2Njg5YTQzZmNmYzdmZTU5NjE0M2QwYjM5OTk2MGE2YjIxODFiMTdjNjMwNjFiOTM4Y2YyYTBhMzNmYTc5MzAxMzZmZjgyYTU1ZTk0ZjYwZGRkZmYzYjU1OWUwYjY4NTY1MjhmNTViMjhmMDYyMGY0MzY0OTJhZTY1YTFlNDEzOTViZTBkZjJmZTkyMmZhZWU3YmU4NDJiYjk2MDE5YjFlYTMzNDNiYTdjOTE1NTMwMjg5MGNjNTRhMmIwYzZiODVlNA==</encrypt><merchant>22294531</merchant><version>V2.0</version></jdpay>'
        encrypt_begin = xml_str_with_encrypt.find('<encrypt>')
        encrypt_end = xml_str_with_encrypt.find('</encrypt>')
        encrypt_str = xml_str_with_encrypt[encrypt_begin + 9:encrypt_end]

        # 测试反解密
        jm_str = self.decode_des(encrypt_str, self.MERCHANT_DESKEY)
        sign_begin = jm_str.find('<sign>')
        sign_end = jm_str.find('</sign>')
        sign_str2 = jm_str[sign_begin + 6:sign_end]
        # 测试代码结束——————————

        res = requests.post(to_url, data=xml_str_with_encrypt, headers={"content-type": "application/xml"})

        encrypt_begin = res.text.find('<encrypt>')
        encrypt_end = res.text.find('</encrypt>')
        encrypt_str = res.text[encrypt_begin + 9:encrypt_end]

        jm_str2 = self.decode_des(encrypt_str, self.MERCHANT_DESKEY)

        # 解密并验证，成功则返回没有sign的xml字符串，否则返回None
        xml_new_str = JdPay.notify_verify(res.text, settings.MERCHANT_DESKEY, settings.MERCHANT_RSA_PUB_KEY)

        return xml_new_str

    def refund(self, **kwargs):
        """
        
        Args:
            **kwargs: 
            tradeNum(str): 1. 不支持批量退款，格式为数字或字母，用于标识本次退款请求；2.支持多次部分退款，退款总金额需小于实收总金额，每次退款交易流水号需不同
            oTradeNum(str): 格式为数字或字母的字符串，其值为需要退款的原支付的交易流水号。
            tradeTime(str): 订单生成时间。格式：“yyyyMMddHHmmss”
        Returns:
    
        """
        """ 发送明文报文示例
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <jdpay>
            <amount>1</amount>
            <currency>CNY</currency>
            <merchant>22294531</merchant>
            <notifyUrl>http://10.13.81.116:63917/AsynNotifyHandler.ashx</notifyUrl>
            <oTradeNum>1494236491939</oTradeNum>
            <tradeNum>1494236491939_r</tradeNum>
            <tradeTime>20170508174906</tradeTime>
            <version>V2.0</version>
            <sign>UlcPzSqTH+E/zCqZFUFsY+zZ7mj7sS1XF9By2HEb9a0v6s0px6cUjTMU8J5YmJ521DkePRDiA3XX\rISls9XDISsZvRXJBfBe9pOLf09HzJza45x4iMuuSyxeaGEGLHo5b9bAGslcwFPNZ14yxbGcptQ4t\rcvO30yNDbsWroTMzGZo=</sign>
        </jdpay>        
        """

        if "amount" not in kwargs:
            raise JdException("缺少申请退款必填参数amount")
        if "oTradeNum" not in kwargs:
            raise JdException("缺少申请退款必填参数oTradeNum")
        if "tradeTime" not in kwargs:
            raise JdException("缺少申请退款必填参数tradeTime")

        if not self.REFUND_URL:
            raise JdException("缺少申请退款的url")

        params = {
            "version": "V2.0",
            "currency": "CNY",
            "amount": kwargs.get("amount"),

            "merchant": self.MERCHANT,
            "notifyUrl": self.REFUND_NOTIFY_URL,

            "tradeNum": kwargs.get("tradeNum"),
            "tradeTime": kwargs.get("tradeTime"),
            "oTradeNum": kwargs.get("oTradeNum"),
        }

        return self._option_data(params, self.REFUND_URL)
