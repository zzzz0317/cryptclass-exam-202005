import hashlib
import hmac
import zlib
import base64

def zlibs(m):
    return str(base64.b64encode(zlib.compress(m.encode("utf-8"),9)),"utf-8")

def dezlibs(m):
    return str(bytes.decode(zlib.decompress(base64.b64decode(m))))

def genHmac(m, k):
    message = m.encode('utf-8')
    key = k.encode('utf-8')
    h = hmac.new(key, message, digestmod="sha3_256")
    return h.hexdigest()

def genHashKey(m):
    return hashlib.sha3_512((m).encode('utf-8')).hexdigest()

def encrypt(msg, key):
    r = ""
    aa = ""
    for a in msg:
        if aa != "":
            key = genHashKey(aa)
        r += genHmac(a, key)
        aa += a
    return r

def decrypt(msg, key):
    try:
        msg = dezlibs(msg)
    except:
        return "解压缩不正常，请检查消息完整性"
    realLen = len(msg) / 64
    if realLen % 1 != 0:
        print("消息为: " + msg)
        return "解密失败，消息大小不正确！"
    msgList = []
    for i in range(int(realLen)):
        ii = i * 64
        a = msg[ii:ii + 64]
        msgList.append(a)
    result = ""
    for j in msgList:
        b = clash(j, key)
        if (b == False):
            return "解密失败，块" + j + "对撞无结果！"
        result += b
        key = genHashKey(result)
    return result

def clash(h, k):
    for i in range(1114111):
        try:
            a = genHmac(chr(i), k)
            if a == h:
                return chr(i)
        except UnicodeEncodeError:
            pass
    return False

key = ""

def main():
    key = input("请输入密钥:\n")
    while True:
        msg = input("请输入消息:\n")
        mode = input("请选择模式:\n1.加密\n2.解密\n3.修改密钥\n4.退出\n")
        if (mode == "1"):
            print("加密结果:")
            print(zlibs(encrypt(msg, key)))
        elif (mode == "2"):
            print("解密结果:")
            print(decrypt(msg, key))
        elif (mode == "3"):
            key = input("请输入密钥:\n")
            print("密钥修改完成")
        elif (mode == "4"):
            exit(0)
        else:
            print("输入有误，请重新输入")
    print("")

if __name__ == '__main__':
    main()
