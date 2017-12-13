# -*- coding:utf-8 -*-

import time

from django.shortcuts import HttpResponse
from django.views.generic.base import View
from django.conf import settings
from utils.jdpay import JdPay
import json


# import pay2



def ceshi(request):
    jd_pay = JdPay(settings)

    params = {
        "version": "V2.0",

        "tradeNum": JdPay.get_nonce_str(),
        "tradeName": "京东支付测试商户号",
        "tradeTime": time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())),

        "amount": "1",
        "orderType": "0",
        "currency": "CNY",
        "userId": JdPay.get_nonce_str()
    }

    form_str = jd_pay.create_order(**params)

    return HttpResponse(form_str)


class NotifyViewset(View):
    def post(self, request, **kwargs):
        print("异步回调POST")
        print(request.body.encode("utf-8"))
        return HttpResponse("异步回调")


class RedirectViewset(View):
    def get(self, request, **kwargs):
        print("同步跳转")
        return HttpResponse("同步跳转")

    def post(self, request, **kwargs):
        print("同步跳转POST")
        print(request.body.encode("utf-8"))
        return HttpResponse("同步跳转POST")


if __name__ == '__main__':
    print(time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())))
