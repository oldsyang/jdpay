## 说明

做了微信。支付宝和京东支付之后，发现，最扯蛋的支付，肯定是京东支付，要完整开发京东支付，必须要看完京东支付开发者文档的官网每一个角落，绝对不能凭你的任何经验去猜测有些流程，比如公私钥加解密（不看官网，保证你后悔）、发送请求的方式（form表单提交，看了官网你会发现好怪异），支付同步跳转（还是post，fk），支付成功后返回居然没有支付订单号（完全靠自己去维护，fk）

## 技术描点

首先要去看官网的：http://payapi.jd.com/。 项目使用的是pc网页支付


一. 统一下单的接口：https://wepay.jd.com/jdpay/saveOrder

参数说明：http://payapi.jd.com/docList.html?methodName=2

一定要仔细的看这些参数的说明

特殊参数说明如下：

1)  在以上的请求参数中，商户号是在注册开通京东支付功能的时候，京东支付商户管理系统为用户分配的。
2)  用户账号是商户系统的用户账号。
3)  交易流水号是用来标识每次支付请求的号码，需要商户保证在每一次支付请求的时候交易流水号唯一，多次请求不能使用同一交易流水号，否则京东支付服务在处理后面的支付请求时，会把此交易当做重复支付处理。
4)  签名规则详见：“接口安全规范-签名算法”；
5)  为保证信息安全，表单中的各个字段除了merchant（商户号）、版本号（version）、签名（sign）以外，其余字段全部采用3DES进行加密。


二. 生成签名

签名过程分为两步，首先是将原始参数按照规则拼接成一个字符串S1，然后再将S1根据签名算法生成签名字符串sign。
参数原始字符串的拼接规则：

1) 对于POST表单提交的参数：所有参数按照参数名的ASCII码顺序从小到大排序（字典序），使用URL键值对的方式拼接成字符串S1，（如：k1=value1&k2=value2&k3=value3…）
2) 对于XML报文交互的参数：将XML报文的各行去掉空格后直接拼接成一行字符串作为S1。如果报文只有一行则直接作为S1，不需要再进行拼接。

生成签名的过程如下：

1) 对拼接的参数字符串S1通过SHA256算法计算摘要，得到字符串S2；
2) 对字符串S2使用私钥证书进行加密，并进行base64转码，得到签名字符串sign； 接收方收到报文后先进行base64解码，再使用公钥证书解密，然后验证签名的合法性。

注意事项：

1) 空参数不参与签名；
2) 参数列表中的sign字段不参与签名；
3) 为了简化处理，<xml>标签也参与签名；
4) 参数区分大小写；
5) RSA加密的规则为：由交易发起方进行私钥加密，接收方进行公钥解密；（可以使用RSA公私钥校验工具来校验商户RSA公私钥是否匹配）
6) 系统会对商户公钥证书的有效性进行校验。

签名代码：

```python

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

```

三. DES3对每个参数进行加密（merchant（商户号）、版本号（version）、签名（sign）除外）

为防止明文数据在post表单提交的时候暴露，所以京东做了DES3对字段进行加密（不用表单提交不就行了，还搞这么复杂，真该学学支付宝和微信）

京东DES加密说明如下：

```
   除特定说明外，商户和京东支付接口调用报文采用3DES加密，再通过base64转换为字符串。
   3DES加密算法标为DESede，工作模式为电子密码本模式ECB，不填充(DESede/ECB/NoPadding)。
注：服务端NoPadding 为不填充，所以加密的原文字节必须是8的整数倍(如果调用我们提供的加密接口API则不必处理原文字节，加密接口内部已处理)。如果自己实现加密，原文字节不够8的整数倍，则按如下规则转为8的整数倍。
    1.  把原文字符串转成字节数组。
    2.  根据字节数组长度判断是否需要补位。
        补位逻辑为：
        int x = (i+ 4) % 8;
        int y = (x == 0) ? 0 : (8 - x);
        i为字节数组的长度，y为需要补位的长度。
        补位值为0。
    3.  将有效数据长度byte[]添加到原始byte数组的头部。
        i为字节数组的长度。
        result[0] = (byte) ((i >> 24) & 0xFF);
        result[1] = (byte) ((i >> 16) & 0xFF);
        result[2] = (byte) ((i >> 8) & 0xFF);
        result[3] = (byte) (i & 0xFF);

    4.  原文字节数组前面加上第三步的4个字节，再加上需补位的值。
        例如：字符串”1”，转换成字节数组是[49],计算补位y=3, 计算有效数据长度为[0, 0, 0, 1]，最后字节数组为[0, 0, 0, 1, 49, 0, 0, 0]。
Form表单接口的加密方式：
如果商户通过表单方式提交支付请求至收银台，为保证信息安全，表单中的各个字段除了merchant（商户号）、verion（版本号）、sign(签名)以外，其余字段全部采用3DES进行加密。

XML请求接口的加密方式：
通过XML接口方式和京东支付服务器交互的请求，应该对报文进行加密，加密方式为对整个报文整体进行3DES加密，再进行base64转码使其变为可读字符串，加密后的密文置于<encrypt></encrypt>标签中，同时再将报文中的<merchant>（商户号）、<version>（版本号）这两个字段单独置于<jdpay>标签下。

接收到京东支付加密报文后的处理方式：
接收到京东支付返回的加密报文后，先判断<jdpay>标签下的<result>标签的返回码，检查接口调用是否正常返回。然后再读取<encrypt>标签的密文内容进行base64解码，再进行3DES解密，解密后的报文即是原始报文。
```

示例代码：

```python

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
```

这样的话，签名和加密都已完成，往后就拼到页面里的form里

```html
 <form method="post" action="https://wepay.jd.com/jdpay/saveOrder" id="batchForm">
        <input name="merchant" type="hidden" id="merchant" value="22294531" /><br/>
        <input name="notifyUrl" type="hidden" id="notifyUrl" value="da652ac3b881c4ddc2ac26793b20c37fba91a994f108bf8a0a42b5ead05111997bfe2a97eaf4aa49562de1b6d1d32cd7" /><br/>
         <input name="userId" type="hidden" id="userId" value="f23f2b73027cb0f8deb349af3086fdc50f6892f17c9f45b81b6d273d0cdb1cae8151f083427fc8f0" /><br/>
            <input name="sign" type="hidden" id="sign" value="SJ6qfS+9CmXkt6ghJcf9nIdHJDReTFNkRyjFh5XZAsTAtfHT4SdmKeD88t+2dMnaszJ7vVjBnSu64aJyt6SODW2FHJk0WXEvZNixmo2h8F7vHO5lTE2jEG/9uN7sqg2c7kH2Fnu5cFLCeaMfb8uZqZ8CKi+g7Aw4b6rywvoH/8M="
        /><br/>
        <input name="currency" type="hidden" id="currency" value="ac7132c57f10d3ce" /><br/>
         <input name="orderType" type="hidden" id="orderType" value="e00c693e6c5b8a60" /><br/>
         <input name="tradeNum" type="hidden" id="tradeNum" value="05439876d54534c7604c42eca17c14cdf8eece390982627a0799194a74809ee6c9d07d3cff8a7c60"
        /><br/>
         <input name="amount" type="hidden" id="amount" value="e5a6c3761ab9ddaf" /><br/>
        <input name="version" type="hidden" id="version" value="V2.0" /><br/>
        <input name="tradeTime" type="hidden" id="tradeTime" value="d9668085c69c2ecb33367c0710f42c4bc7432967ba39f140"
        /><br/> <input name="tradeName" type="hidden" id="tradeName" value="3e111657e2839e3a3ba10d54bb446817e5000daf14a2e3badbf9a93316ed6003" /><br/>
        <input name="callbackUrl" type="hidden" id="callbackUrl" value="51c916293675ac44c2ac26793b20c37fba91a994f108bf8a0a42b5ead05111997bfe2a97eaf4aa49229a23b8c688e767"
        /><br/><input type="submit" />
    </form>
```

怎么组织就自己去实现好了



四. 异步回调

提交之后请求之后，就会跳转到京东的支付页面，可登录账户支付，也可用京东app或者微信扫描支付。

当用户扫码支付之后，京东会主动跳转到你指定的一个网址（在提交支付请求的时候有这个字段），并且会异步post一个请求到指定的一个地址（在提交支付请求的时候有这个字段），同步跳转是在用户扫码支付之后，如果京东支付页面还在的话会跳转。而异步是无论如何都会发支付结果通知的。对于新手来说，一定要知道这个行业潜规则（微信，支付宝or其它都是）。而且一定要以这个异步通知的结果为准。

京东返回的是xml格式的字符串

返回格式如下（没有换行的，我这里演示换了行的）：

```
<?xml version=\"1.0\" encoding=\"UTF-8\" ?>
<jdpay>
<version>V2.0</version>
<merchant>22294531</merchant>
<result> <code>000000</code> <desc>success</desc> </result>
<encrypt>MWYxMjBjMzViZjgwOWM5ZDhjNjc0YmY1ZWJlY2QyODU0YTc5NmQ3ZWQxMWU1NzE3MWQ0OTUwOGI5NzllYmE4ZjM1YzRiZjlmYWE1M2ZiYjVmYzBmYTgyMDYyM2Q0YjM0NGM1ODFkZDhlYTA2Mjk0ZDE5ZDBlZDk5NTc3MmE4Nzk4OTFlYjIwZDgzMTc4MDU3NGVkZTFjNDY0MDMzNzNjZjc2OWZiMDQ0YjVhZGNhYmRhMGZmYTkyNzRhZDNhM2IxOGY5ZjZhYjBmYjhmZmI3Yzg0OTA3YzM0OGJmZTYwZTIzNzM3YjVmYzMzNmNkYTE0MjM2OWIwZDM5MjI2YWM5YmY3ZmZjZDBkNWJmM2ZkYWY4YTU3OWU4MDE3ZjQ5YmQ0ZWIyMDA0NTFmODZkNmViMDBiMDE2YTU3NTNjMzJjNDIzNWI5ZDkyYzQ3OTU4OTc2ZGIyZmNiMGUxNGRjNTM2OGZjYjQ0NmE0YWY1ZWVjZDYzNWI5ZDkyYzQ3OTU4OTc2NmIwM2QyZTU1ODJlNDNjM2M1NjA2YmQ5ZDc3MTRkMmNjN2ZiMDM3Yzg5ZDk1ODFkMWJhZmVjYjUwMzJlNTdkMTFmN2QxMDAxNjgyMzJjNTZhMmQzNTcyZGE4OTUzYWFjNTU5MDY4YWYyODE5ZDcyNmY5NmE1YTBmYWFiZTRiZTQ2OGZhMmM4M2JjMGM5NmNiMDE3ZWQ4MDkxY2FjZThiNzg4MjY5OWY1ZTJlYzBjOTIxODBhOGExNjExNGY4NWQwM2NkZjI2MTFmM2VmODcxYWM3MjUxZjMxMzZlYjFmNzI1NWE0OWM4MjMxZGY1MzBmY2Y1Mjg2NGUzMWRlMjc0M2I5ZDM5NjQzN2ZmZWQ1Y2M5NDY4ZDcwNWM1YzVhZmRlYzYwZWU3MDVhNjE0N2I1MGVlM2UyMGE2MzExNTE4YTUxOGRjMzBmMmUxZjE2NzYzNGRiNDJlODFmMDczOGYzZjMxN2NkMjkzNmU4ODc3NzJjMjkzM2ZlODlmMjUyNDVmNDI2MDA0M2VkYmUwOTlkNGEyNjU3YTM5YTE4ODU2OTBmNGQyNDcwZDE0ZWRjMmQxYjgxMzhhNjA5M2ZlNDkxYTQyMzE5YzBlNTA0MTdkYTg2ZGQ2NDQwODBmMjM4ZGI2YzIzMjNhOTE0M2VmMjZiZjczN2M5NWQwODYxMWY2OGE5MDQ0ZDZmNzE0NmIxZjQwZDdmZDMxOTQ2ZDM3YjIwNDJiODUzZGM0NTk0MzM5YzJkN2M2NDdiNGM4MzQ4MTRjZTIxZTlmYTYzNDYxNGMxMjlhZTE3NjE0ZDIzM2Q2MTQ4YzJiNWE3ZWVjMDU5MjFmNzJkNGNjNTU1NWZkNzVhN2U5Y2I1MDU1NjhlMWRlNjVhNzkyOGUxMThlODQyMGJkNzE2NjdmMDc3YmEyYTFkNmQyOTFiOGNjZTU2ZGMyYmE3ODY5ZGZiNmMyMWViYjc2ODc0Y2I3YTc4NGQ5NWY2NjY2Y2E5NjI0N2I1MGE4MTliMDBkNGIzNmViZTJlY2JmYTcwODUzYTM5ZTcwMDVmYWEzNWY2MDFhMWM2MGQ1MzEyYmQxNDU3Zjg4ZWVhNzY2YjZhOGE4ZGMxMGY3NjYwOWEzNWY2MDFhMWM2MGQ1MzFhNzA4NTNhMzllNzAwNWZhYTYxMmJmNjJiMmFlMGY5ODMxMzQ0MzQ0NjMxZDc3MTUyY2FiMjZlMjcyYmJjYmQzODVmNDY4OTA5YTdjMjlmNTI5NWFlZjE3NTI4ZmE4MzVhNzA4NTNhMzllNzAwNWZhNDk5OTQ2ZGU0OGU0NGQ2ZTE4YmRiYTBjZjNhM2ZkNjY5ODJjNGVhZjQzMjIyYWFhMWM0ZmU1ODRiNTg5OWEwYzAwNjI2NTllMDZkYzhiYTVmMjI3ZjUyYmQ3MjcyODllZmEwYzhiNDIwODc4ZjUzODY1MzAzZDkyNDM5OTRkNDczMTBjZDBhMTc4ZjAwOTIyZmM2ODk5YjkyYTJiODcwNjU4MzkzMzJkZWYzNDY1MzJlYTNiYTFhNjM0MWIwNjM4NjBjNjlmMzg1NWZjZWM5YWExMDdjZWY1MjkwZTZjMzgzOGYxNTRiNzFlN2E1YTczYWFkNzJlOTRiOWI3MmI2YWYyMTJjMjQ5Y2UzMmUxMGI4YWE0N2YzYzFmNjNiOGY4NjJlZmU1ZDM5NjcwODA3MGNjY2JjYWFkYjM3NzBmMGQzYjIyMGFmZTE3YWNjZWU1N2RmZTQxMzAxYjA2MDdlMg==</encrypt>
</jdpay>
```

先要用DES3对encrypt节点里的串进行解密

```python

def un_des_pad(data):
    resultByte = data[0:4]
    e = struct.unpack('>I', resultByte)[0]
    x = (e + 4) % 8
    y = 0 if x == 0 else 8 - x
    return data[4:] if y == 0 else data[4:-y]

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


sign_begin = xml_data.find('<encrypt>')
sign_end = xml_data.find('</encrypt>')
encrypt_str = xml_data[sign_begin + 9:sign_end]
xml_str = JdPay.decode_des(encrypt_str, deskey)
```

解密后的明文如下：

```xml
<?xml version="1.0" encoding="UTF-8" >
<jdpay>
  <version>V2.0</version>
  <merchant>110290193003</merchant>
<result>
  <code>000000</code>
  <desc>success</desc>
</result>
<device>6220</device>
<sign>SJ6qfS+9CmXkt6ghJcf9nIdHJDReTFNkRyjFh5XZAsTAtfHT4SdmKeD88t+2dMnaszJ7vVjBnSu64aJyt6SODW2FHJk0WXEvZNixmo2h8F7vHO5lTE2jEG/9uN7sqg2c7kH2Fnu5cFLCeaMfb8uZqZ8CKi+g7Aw4b6rywvoH/8M=</sign>
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

```

解密之后就是验证签名是否正确,从上边的串中拿到签名和去除签名之后的字符串

```python
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
```

验证通过之后再返回去除sign的xml字符串，并提取出里边的内容（详情参数所代表的含义请看官方文档）


五. 同步跳转

同步跳转就没啥好说了，只是给个跳转地址，但是这里一定要注意，这个的是一个post请求（好像京东啥都喜欢post），而非微信或者支付宝或者other什么的get请求。所以不要设置错了

好了，到这里一个完整的在线支付就完成了。这里还要说明的是，涉及到加密和解密，就一定会有key，有DES3使用的对称加密key，还有签名使用的非对称公钥和私钥。所以一定要配置好。
这里我的源代码里用的都是京东提供的测试商户号，还有一大推京东设置好的key，具体要去下载京东的【京东支付PC&H5接口文档】，在文档的最底部有帐号信息。

demo里边还有申请退款，申请撤单的接口，其实写好一个接口的完成流程，别的流程都是直接套用就可以了。

