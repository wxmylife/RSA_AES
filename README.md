#移动端和WEB端的混合加密（RSA和AES）
********


##流程
是先由服务器创建RSA密钥对，RSA公钥保存在安卓的so文件里面，服务器保存RSA私钥。而安卓创建AES密钥（这个密钥也是在so文件里面），并用该AES密钥加密待传送的明文数据，同时用接受的RSA公钥加密AES密钥，最后把用RSA公钥加密后的AES密钥同密文一起通过Internet传输发送到服务器。当服务器收到这个被加密的AES密钥和密文后，首先调用服务器保存的RSA私钥，并用该私钥解密加密的AES密钥，得到AES密钥。最后用该AES密钥解密密文得到明文

![数据加密流程](https://github.com/wxmylife/RSA_AES/blob/master/img/1.png)



####推荐文章
[Android数据加密方案](http://www.jianshu.com/p/d4fee3a2de82)

[Android数据加密之RSA加密](http://www.cnblogs.com/whoislcj/p/5470095.html)

[Android数据加密之Aes加密](http://www.cnblogs.com/whoislcj/p/5473030.html)
##制作RSA公钥和私钥
* 新建一文件夹，用终端进入到该文件夹下

![效果示例](https://github.com/wxmylife/RSA_AES/blob/master/img/2.png)

* 打开mac自带的OpenSSL

![效果示例](https://github.com/wxmylife/RSA_AES/blob/master/img/3.png)

* 通过如下命令生成私钥：`genrsa -out rsa_private_key.pem 2048`，生成了一份私钥，加密长度是2048位， 密钥长度，范围：512～2048, 内容是标准的ASCII字符

![效果示例](https://github.com/wxmylife/RSA_AES/blob/master/img/4.png)

* 通过如下命令生成公钥：

	`rsa -in rsa_private_key.pem -out rsa_public_key.pem -pubout`
	
![效果示例](https://github.com/wxmylife/RSA_AES/blob/master/img/5.png)

* 这样密钥就基本生成了，不过这样密钥对的私钥是无法在代码中直接使用的，要想使用它需要借助RSAPrivateKeyStructure这个类，Java是不自带的。所以为了方便使用，我们需要对私钥进行PKCS#8编码，命令如下：

`pkcs8 -topk8 -in rsa_private_key.pem -out pkcs8_rsa_private_key.pem -nocrypt` 

![效果示例](https://github.com/wxmylife/RSA_AES/blob/master/img/6.png)

* 所有步骤完成，最终如下图

![效果示例](https://github.com/wxmylife/RSA_AES/blob/master/img/7.png)
***
##测试代码
```
	 	//得到AES加密随机生成的密钥匙
		String aesKey=  AESUtils.generateKeyString();
		System.out.println("AES秘钥为-------->>>>"+aesKey);
		System.out.println("<<<<---------------------------------------->>>>");
		//获取加密数据
		String context=initData();
		
		//AES加密生成密文
		String aesToContext=AESUtils.encrypt(context, aesKey);
		System.out.println("AES加密后密文为-------->>>>"+aesToContext);
		System.out.println("<<<<---------------------------------------->>>>");
		//获取RSA公钥
		RSAPublicKey publicKey=RSAUtils.loadPublicKey(new FileInputStream("rsa_public_key.pem文件路径"));
		//RSA公钥加密AES生成的密钥匙
		String rsaAesKey=RSAUtils.encryptByPublicKey(aesKey, publicKey);
		System.out.println("RSA加密后密钥为-------->>>>"+rsaAesKey);
		
		
		
		System.out.println("<<<<---------------------------------------->>>>");
		//获取RSA私钥路径
		RSAPrivateKey privateKey=RSAUtils.loadPrivateKey(new FileInputStream("pkcs8_rsa_private_key.pem文件路径"));
		//RSA私钥解密加密过后的AES生成的密钥匙
		String aesRKey=RSAUtils.decryptByPrivateKey(rsaAesKey, privateKey);
		System.out.println("RSA解密后密钥为-------->>>>"+aesRKey);
		String txt=AESUtils.decrypt(aesToContext, aesRKey);
		System.out.println("AES解密后密文为-------->>>>"+txt);```