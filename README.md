# 内网安全

## kerberos协议

### PTK

Kerberos 身份验证协议使用票证来授予访问权限。出示 TGT（Ticket Granting Ticket）可以获得服务票证（ST）。可以通过验证名为“预身份验证”的第一步来获得先前的 TGT（除非明确删除某些帐户的要求，使它们容易受到[ASREProast]()的攻击）。

预认证要求请求用户提供从用户密码派生的密钥（DES、RC4、AES128 或 AES256）。知道密钥的攻击者不需要知道实际密码来获取票证。这称为传递密钥。

Kerberos 提供 4 种不同的密钥类型：DES、RC4、AES-128 和 AES-256。

当启用 RC4 etype 时，可以使用 RC4 密钥。问题在于 RC4 密钥实际上是用户的 NT 哈希。使用 NT 散列来获取 Kerberos 票证被称为[**通过散列**]()。

禁用 RC4 时，也可以传递其他 Kerberos 密钥（DES、AES-128、AES-256）。这种技术称为**传递密钥**。其实overpass hash和pass key只是name和key不同而已，技术是一样的。



impacket脚本[getTGT](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) (Python) 可以在给定密码、哈希值（可以为空）或 aesKey 的情况下请求TGT（票证授予票证）。TGT 将被保存为一个文件，然后可以被其他 Impacket 脚本使用。`LMhash``.ccache`

\# 使用 NT 哈希（overpass-the-hash）

getTGT.py -哈希'LMhash:NThash' $DOMAIN / $USER @ $TARGET  

\# 使用 AES（128 或 256 位）密钥（传递密钥）

getTGT.py -aesKey 'KerberosKey' $DOMAIN / $USER @ $TARGET 

获得 TGT 后，测试人员可以将其与环境变量一起使用，并使用实现`KRB5CCNAME`[pass-the-ticket 的]()工具。

请求 TGT 然后传递票证的替代方法是使用`-k`Impacket 脚本中的选项。使用该选项允许传递 TGT 或 ST。下面的示例带有 secretsdump。

secretsdump.py -k -hashes 'LMhash:NThash' $DOMAIN / $USER @ $TARGET   



### PTT

有一些方法可以找到（[缓存的 Kerberos 票证]()）或伪造（[通过散列]()、[银票]()和[金票]()攻击）Kerberos 票。然后可以使用票证在不知道任何密码的情况下使用 Kerberos 对系统进行身份验证。这叫做[通票]()。另一个名称是传递缓存（当使用来自类 UNIX 系统或在类 UNIX 系统上找到的票证时）。

而其中缓存的kerberos票证就是MS14068 也可以说是PTC技术

PTC它不是使用来自 Windows 系统或在 Windows 系统上找到的 Kerberos 票证，而是基于服务于完全相同目的的类 UNIX 格式化票证

*Nix 操作系统，如 Mac OS， Linux，BSD， Unix，等等会将 Kerberos 凭证进行缓存。这些已经被缓存的文件通过使用 Mimikatz 可以被复制以及传递。同样对将 Kerberos 票证注入到缓存文件中也很有用。

一个很好的例子是在[使用 PyKEK 利用 MS14-068 漏洞](https://adsecurity.org/?p=676)时所使用的 Mimikatz 的 **kerberos::ptc** 命令。PyKEK 生成了一个缓存文件，使用 Mimikatz 的 **kerberos::ptc** 命令可以注入操作。

#### 钻石票据

1.在没有特权属性证书（PAC）的情况下请求TGT

2. 确保要访问的服务的服务帐户没有[在其 UserAccountControl (UAC) 属性中设置“NA”位](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557)

UAC 属性中的 NA 位的值为***33554432***：

“PAC”代表“特权认证证书”。它是票证（TGT 或服务票证）中包含的一组特殊数据，提供有关请求用户的信息（用户名、组、UserAccountControl 等）。

[Diamond Ticket 攻击的第一部分（由Charlie Clark](https://twitter.com/exploitph)和[Andrew Schwartz](https://twitter.com/4ndr3w6s)介绍）是获取 TGT。这可以通过使用以下技术之一来完成：

- 对手将使用低权限用户的凭据来启动 KRB_AS_REQ，这将导致合法的 TGT。
- 一个名为[Rubeus的工具有一个名为](https://github.com/GhostPack/Rubeus)[tgtdeleg](https://github.com/GhostPack/Rubeus#tgtdeleg)的选项，它滥用 Kerberos[通用安全服务应用程序接口 (GSS-API)](https://en.wikipedia.org/wiki/Generic_Security_Services_Application_Program_Interface)来为当前用户检索可用的 TGT，而无需在主机上进行提升。

[一旦在KRB_AS_REP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13)中收到 TGT ，对手现在可以使用 KRBTGT 帐户的密钥解密 TGT 并修改票证的每个部分。

修改票证后，攻击者可以使用以下方法之一提升他们的权限：

- 生成 TGT 以模拟域管理员或域中的任何其他用户。

在这种情况下，攻击者需要更改票证中的 cname 字段以及 PAC。此方法将导致以域管理员（或域中的任何其他用户）的名义伪造票证，这与[Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)攻击非常相似。

- 通过修改 PAC 将普通域用户的权限提升为域管理员权限。

  引用https://www.trustedsec.com/blog/a-diamond-in-the-ruff/   https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/#post-126011-_k56ak9qw5q5d
