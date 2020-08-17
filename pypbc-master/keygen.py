#coding:utf8
# pupulate-pub-key-v3.py
#
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
pub_key="EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443"# ===>新浪微博的公钥模数，抓包而来

# 从little-endian格式的数据缓冲data中解析公钥模数并构建公钥
def populate_public_key(data):
    # convert bytes to integer with int.from_bytes
    # 指定从little格式将bytes转换为int，一句话就得到了公钥模数，省了多少事
    n = int(data,16)
    e = 65537

    # 使用(e, n)初始化RSAPublicNumbers，并通过public_key方法得到公钥
    # construct key with parameter (e, n)
    key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    return key


# 将公钥以PEM格式保存到文件中
def save_pub_key(pub_key, pem_name):
    # 将公钥编码为PEM格式的数据
    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # print(pem)

    # 将PEM个数的数据写入文本文件中
    with open(pem_name, 'w+') as f:
        f.writelines(pem.decode())

    return

if __name__ == '__main__':
        pub_key = populate_public_key(data=pub_key)
        pem_file = 'pub_key.pem'
        save_pub_key(pub_key, pem_file)

