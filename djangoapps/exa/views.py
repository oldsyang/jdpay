# -*- coding:utf-8 -*-

import time

from django.shortcuts import HttpResponse
from django.views.generic.base import View
from django.conf import settings
from utils.jdpay import JdPay
import json


# import pay2



def create_order(request):
    """
    在线支付接口测试
    Args:
        request: 

    Returns:

    """
    jd_pay = JdPay(settings)

    trade_num = JdPay.get_nonce_str()
    params = {
        "version": "V2.0",

        "tradeNum": trade_num,
        "tradeName": "京东支付测试商户号",
        "tradeTime": time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())),

        "amount": "1",
        "orderType": "0",
        "currency": "CNY",
        "userId": JdPay.get_nonce_str()
    }

    print("trade_num:", trade_num)
    form_str, params = jd_pay.create_order(**params)
    print("form_str:", type(form_str))
    # return HttpResponse(form_str)

    # ce_str = "MWYxMjBjMzViZjgwOWM5ZDhjNjc0YmY1ZWJlY2QyODU0YTc5NmQ3ZWQxMWU1NzE3MWQ0OTUwOGI5NzllYmE4ZjM1YzRiZjlmYWE1M2ZiYjVmYzBmYTgyMDYyM2Q0YjM0NGM1ODFkZDhlYTA2Mjk0ZDE5ZDBlZDk5NTc3MmE4Nzk4OTFlYjIwZDgzMTc4MDU3NGVkZTFjNDY0MDMzNzNjZjc2OWZiMDQ0YjVhZGNhYmRhMGZmYTkyNzRhZDNhM2IxOGY5ZjZhYjBmYjhmZmI3Yzg0OTA3YzM0OGJmZTYwZTIzNzM3YjVmYzMzNmNkYTE0MjM2OWIwZDM5MjI2YWM5YmY3ZmZjZDBkNWJmM2ZkYWY4YTU3OWU4MDE3ZjQ5YmQ0ZWIyMDA0NTFmODZkNmViMDBiMDE2YTU3NTNjMzJjNDIzNWI5ZDkyYzQ3OTU4OTc2ZGIyZmNiMGUxNGRjNTM2OGZjYjQ0NmE0YWY1ZWVjZDYzNWI5ZDkyYzQ3OTU4OTc2NmIwM2QyZTU1ODJlNDNjM2M1NjA2YmQ5ZDc3MTRkMmNjN2ZiMDM3Yzg5ZDk1ODFkMWJhZmVjYjUwMzJlNTdkMTFmN2QxMDAxNjgyMzJjNTZhMmQzNTcyZGE4OTUzYWFjNTU5MDY4YWYyODE5ZDcyNmY5NmE1YTBmYWFiZTRiZTQ2OGZhMmM4M2JjMGM5NmNiMDE3ZWQ4MDkxY2FjZThiNzg4MjY5OWY1ZTJlYzBjOTIxODBhOGExNjExNGY4NWQwM2NkZjI2MTFmM2VmODcxYWM3MjUxZjMxMzZlYjFmNzI1NWE0OWM4MjMxZGY1MzBmY2Y1Mjg2NGUzMWRlMjc0M2I5ZDM5NjQzN2ZmZWQ1Y2M5NDY4ZDcwNWM1YzVhZmRlYzYwZWU3MDVhNjE0N2I1MGVlM2UyMGE2MzExNTE4YTUxOGRjMzBmMmUxZjE2NzYzNGRiNDJlODFmMDczOGYzZjMxN2NkMjkzNmU4ODc3NzJjMjkzM2ZlODlmMjUyNDVmNDI2MDA0M2VkYmUwOTlkNGEyNjU3YTM5YTE4ODU2OTBmNGQyNDcwZDE0ZWRjMmQxYjgxMzhhNjA5M2ZlNDkxYTQyMzE5YzBlNTA0MTdkYTg2ZGQ2NDQwODBmMjM4ZGI2YzIzMjNhOTE0M2VmMjZiZjczN2M5NWQwODYxMWY2OGE5MDQ0ZDZmNzE0NmIxZjQwZDdmZDMxOTQ2ZDM3YjIwNDJiODUzZGM0NTk0MzM5YzJkN2M2NDdiNGM4MzQ4MTRjZTIxZTlmYTYzNDYxNGMxMjlhZTE3NjE0ZDIzM2Q2MTQ4YzJiNWE3ZWVjMDU5MjFmNzJkNGNjNTU1NWZkNzVhN2U5Y2I1MDU1NjhlMWRlNjVhNzkyOGUxMThlODQyMGJkNzE2NjdmMDc3YmEyYTFkNmQyOTFiOGNjZTU2ZGMyYmE3ODY5ZGZiNmMyMWViYjc2ODc0Y2I3YTc4NGQ5NWY2NjY2Y2E5NjI0N2I1MGE4MTliMDBkNGIzNmViZTJlY2JmYTcwODUzYTM5ZTcwMDVmYWEzNWY2MDFhMWM2MGQ1MzEyYmQxNDU3Zjg4ZWVhNzY2YjZhOGE4ZGMxMGY3NjYwOWEzNWY2MDFhMWM2MGQ1MzFhNzA4NTNhMzllNzAwNWZhYTYxMmJmNjJiMmFlMGY5ODMxMzQ0MzQ0NjMxZDc3MTUyY2FiMjZlMjcyYmJjYmQzODVmNDY4OTA5YTdjMjlmNTI5NWFlZjE3NTI4ZmE4MzVhNzA4NTNhMzllNzAwNWZhNDk5OTQ2ZGU0OGU0NGQ2ZTE4YmRiYTBjZjNhM2ZkNjY5ODJjNGVhZjQzMjIyYWFhMWM0ZmU1ODRiNTg5OWEwYzAwNjI2NTllMDZkYzhiYTVmMjI3ZjUyYmQ3MjcyODllZmEwYzhiNDIwODc4ZjUzODY1MzAzZDkyNDM5OTRkNDczMTBjZDBhMTc4ZjAwOTIyZmM2ODk5YjkyYTJiODcwNjU4MzkzMzJkZWYzNDY1MzJlYTNiYTFhNjM0MWIwNjM4NjBjNjlmMzg1NWZjZWM5YWExMDdjZWY1MjkwZTZjMzgzOGYxNTRiNzFlN2E1YTczYWFkNzJlOTRiOWI3MmI2YWYyMTJjMjQ5Y2UzMmUxMGI4YWE0N2YzYzFmNjNiOGY4NjJlZmU1ZDM5NjcwODA3MGNjY2JjYWFkYjM3NzBmMGQzYjIyMGFmZTE3YWNjZWU1N2RmZTQxMzAxYjA2MDdlMg=="
    # form_str = jd_pay.unsign(ce_str)

    # print("source_str:", form_str)

    return HttpResponse(form_str)


def revoke(requset):
    """
    撤销申请接口：提供给商户发起自动撤销的能力。对于未支付的订单撤销后不可再次支付，对于支付成功的订单则发起退款。
    Args:
        requset: 

    Returns:

    """
    """
    发送的明文报文如下（最后要加密发送的，没有换行）：
    
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>
    <jdpay>
    <amount>1</amount>
    <currency>CNY</currency>
    <merchant>22294531</merchant>
    <note></note>
    <oTradeNum>asd784374823472389</oTradeNum>
    <tradeNum>asd784374823472389_r</tradeNum>
    <tradeTime>20170510162925</tradeTime>
    <version>V2.0</version>
    <sign>YmN329jSDx9gv4ZJzYKfF1F2Mnff1uRablYNcdmRn37dZZXEGSCPqD6tvikn9VtyD4efd8lAvzi6\rb30/t5Soyn0W1jPmOWRjIy20zMLL+vD7NBPejPjR7QXgty6IBOwikZICxTsY1oyVrJu40m0CTFap\rRwhBWtSBctyI1HgXjEo=</sign>
    </jdpay>
    """

    params = {
        "version": "V2.0",
        "currency": "CNY",
        "amount": "1",
        "note": "2323",
        "tradeNum": JdPay.get_nonce_str(),
        "tradeTime": time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())),
        "oTradeNum": "Kbpt244GKVenJOGGsT5rp5dgVDR0wAZp",
    }
    jd_pay = JdPay(settings)
    res = jd_pay.revoke(**params)

    """
        处理返回后的报文如下：res http://payapi.jd.com/docList.html?methodName=2
        
       <?xml version=\"1.0\" encoding=\"UTF-8\"?>
       <jdpay>
       <version>V2.0</version>
       <merchant>22294531</merchant>
       <result><code>000000</code><desc>成功</desc></result>
       <tradeNum>asd784374823472389_r</tradeNum>
       <tradeType>2</tradeType>
       <oTradeNum>asd784374823472389</oTradeNum>
       <amount>1</amount>
       <currency>CNY</currency>
       <tradeTime>20170510162925</tradeTime>
       <note></note>
       <status>1</status>
       </jdpay>
       """
    return HttpResponse(res)


def refund(request):
    """
    申请退款接口测试
    Args:
        request: 

    Returns:

    """
    jd_pay = JdPay(settings)
    """
    发送的报文示例（没有换行）
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>
    <jdpay>
    <amount>1</amount>
    <currency>CNY</currency>
    <merchant>22294531</merchant>
    <note></note>
    <notifyUrl>http://10.13.81.116:63917/AsynNotifyHandler.ashx</notifyUrl>
    <oTradeNum>1494236491939</oTradeNum>
    <tradeNum>1494236491939_r</tradeNum>
    <tradeTime>20170508174906</tradeTime>
    <version>V2.0</version>
    <sign>UlcPzSqTH+E/zCqZFUFsY+zZ7mj7sS1XF9By2HEb9a0v6s0px6cUjTMU8J5YmJ521DkePRDiA3XX\rISls9XDISsZvRXJBfBe9pOLf09HzJza45x4iMuuSyxeaGEGLHo5b9bAGslcwFPNZ14yxbGcptQ4t\rcvO30yNDbsWroTMzGZo=</sign>
    </jdpay>
    """

    params = {
        "version": "V2.0",
        "currency": "CNY",
        "amount": "1",
        "note": "2323",
        "tradeNum": JdPay.get_nonce_str(),
        "tradeTime": time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())),
        "oTradeNum": "1RX2V9OGlTBxkeEX48x41MkelhJoETo9",
    }
    res = jd_pay.refund(**params)

    """
    处理返回后的报文如下：res http://payapi.jd.com/docList.html?methodName=2

    <?xml version="1.0" encoding="UTF-8"?>
    <jdpay>
    <merchant>22294531</merchant>
    <result>
        <code>000000</code>
        <desc>\xe6\x88\x90\xe5\x8a\x9f</desc>
    </result>
    <tradeNum>bVBShsFS2MMmfipjJ9weM2Rm7pW8Ksmr</tradeNum>
    <oTradeNum>aQEBuLdpX2DExSMtsGFU4y3Rv4Ln3Gt3</oTradeNum>
    <amount>1</amount>
    <currency>CNY</currency>
    <tradeTime>20171214133000</tradeTime>
    <status>1</status>
    </jdpay>
    """
    return HttpResponse(res)


def refund_notify(request):
    """
    申请退款异步回调接口测试
    Args:
        request: 

    Returns:

    """
    print("申请退款异步回调")
    print("refund_notify_request.body:", request.body)
    encrypt_begin = request.body.find('<encrypt>')
    encrypt_end = request.body.find('</encrypt>')
    encrypt_str = request.body[encrypt_begin + 9:encrypt_end]

    # 解密
    # jm_str = JdPay.decode_des(encrypt_str, settings.MERCHANT_DESKEY)

    # 解密并验证，成功则返回没有sign的xml字符串，否则返回None
    xml_new_str = JdPay.notify_verify(request.body, settings.MERCHANT_DESKEY, settings.MERCHANT_RSA_PUB_KEY)

    print("xml_new_str:", xml_new_str)
    """
    接收报文示例：xml_new_str：http://payapi.jd.com/docList.html?methodName=2
    
    <?xml version="1.0" encoding="UTF-8" ?>
    <jdpay>
    <merchant>22294531</merchant>
    <tradeNum>bVBShsFS2MMmfipjJ9weM2Rm7pW8Ksmr</tradeNum>
    <tradeType>1</tradeType>
    <result>
        <code>000000</code>
        <desc>success</desc>
    </result>
    <sign>JGr57yzU8uOC3XKqumwKPMKqfME6As7T7naygyiUa7QqX9qKZTqfjtjfk9JQqI2nFV/IqPrUIBHfetZKyFYgR22IKkqKyj7LXx9Z00TE2laCJd87cA5RUHgpp9aUf5G68wmWlpVIGro3gVqnF2lNmWBM4FpDJ+QJ3jZH2Eqji+A=</sign>
    <oTradeNum>aQEBuLdpX2DExSMtsGFU4y3Rv4Ln3Gt3</oTradeNum>
    <amount>1</amount>
    <currency>CNY</currency>
    <tradeTime>20171214133000</tradeTime>
    <status>1</status>
    </jdpay>
    """
    return HttpResponse(request.body)


class NotifyViewset(View):
    """
    在线支付异步回调
    """

    def post(self, request, **kwargs):
        print("异步回调POST")

        # 解密报文（含sign）
        # source_str = JdPay.decode_des(ce_str, settings.MERCHANT_DESKEY)

        # 返回已经解密并验证通过的xml字符串
        print("request.body_nofify:", request.body)
        encrypt_begin = request.body.find('<encrypt>')
        encrypt_end = request.body.find('</encrypt>')
        encrypt_str = request.body[encrypt_begin + 9:encrypt_end]

        xml_new_str = JdPay.notify_verify(request.body, settings.MERCHANT_DESKEY, settings.MERCHANT_RSA_PUB_KEY)
        """
           xml_new_str；参数参考http://payapi.jd.com/docList.html?methodName=2
           
           <?xml version="1.0" encoding="UTF-8" >
           <jdpay>
             <version>V2.0</version>
             <merchant>110290193003</merchant>
           <result>
             <code>000000</code>
             <desc>success</desc>
           </result>
           <device>6220</device>
           <tradeNum>201704250935156041484635</tradeNum>
           <tradeType>0</tradeType>
           <amount>3140</amount>
           <status>2</status>
           <payList>
             <pay>
               <payType>3</payType>
               <amount>1500</amount>
               <currency>CNY</currency>
               <tradeTime>20170425093516</tradeTime>
            </pay>
            <pay>
              <payType>1</payType>
              <amount>1640</amount>
              <currency>CNY</currency>
              <tradeTime>20170425093516</tradeTime>
              <detail>
                <cardHolderMobile>150****1596</cardHolderMobile>
              </detail>
             </pay>
           </payList>
           </jdpay>
        """

        return HttpResponse("ok")


class RedirectViewset(View):
    """
    在线支付跳转
    """

    def post(self, request, **kwargs):
        print("同步跳转POST")
        print(request.body.encode("utf-8"))
        return HttpResponse("同步跳转POST")


if __name__ == '__main__':
    print(time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())))
