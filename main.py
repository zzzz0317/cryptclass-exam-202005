import hashlib

def encrypt(msg, key):
    r = ""
    for a in msg:
        r += hashlib.md5((a + key).encode('utf-8')).hexdigest()
    return r

def decrypt(msg, key):
    realLen = len(msg)/32
    if realLen % 1 != 0:
        return "解密失败，消息大小不正确！"
    msgList = []
    for i in range(int(realLen)):
        ii = i*32
        a = msg[ii:ii+32]
        msgList.append(a)
    result = ""
    for j in msgList:
        b = clash(j, key)
        if (b == False):
            return "解密失败，块" + j + "对撞无结果！"
        result += b
    return result

def clash(h,k):
    for i in range(55295):
        a = hashlib.md5((chr(i) + k).encode('utf-8')).hexdigest()
        if a == h:
            return chr(i)
    return False

def main():
    key = input("请输入密钥:\n")
    msg = input("请输入消息:\n")
    mode = input("请选择模式:\n1.加密\n2.解密\n")
    if (mode == "1"):
        print("加密结果:")
        print(encrypt(msg, key))
    elif (mode == "2"):
        print("解密结果:")
        print(decrypt(msg, key))

if __name__ == '__main__':
    while(True):
        main()
        print("")
