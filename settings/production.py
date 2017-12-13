# -*- coding: utf-8 -*-
# @Author  : oldsyang

from .common import *

# 商户号（京东公用测试帐号）
MERCHANT = '22294531'

# 对数据加密的DESKEY
MERCHANT_DESKEY = 'ta4E/aspLA3lgFGKmNDNRYU92RkZ4w2t'

# 对数据加密的MD5KEY
MERCHANT_MD5KEY = 'test'

# 私钥路径
MERCHANT_RSA_PRI_KEY = r'exa/key/private_key.pem'

MERCHANT_RSA_PUB_KEY = 'exa/key/jd_public_key.pem'

# 京东公钥（验证）
MERCHANT_WY_RSA_PUB_KEY = 'exa/key/jd_public_key.pem'

# 在线支付接口
PAY_URL = 'https://wepay.jd.com/jdpay/saveOrder'

# 异步接收微信支付结果通知的回调地址，通知url必须为外网可访问的url，不能携带参数。
ASYN_NOTIFY_URL = "http://xxxx.com:8888/test/jdpay/notify"

# 异步接收微信支付结果通知的回调地址，通知url必须为外网可访问的url，不能携带参数。
REDIRECT_URL = "http://xxxx.com:8888/test/jdpay/notify"
