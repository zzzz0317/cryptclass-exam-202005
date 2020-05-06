import hashlib
import hmac
import zlib
import base64
import time


def zlibs(m):
    ec = m.encode("utf-8")
    ziped = zlib.compress(ec, 9)
    b64 = base64.b64encode(ziped)
    s = str(b64, "utf-8")
    return s
    # return str(base64.b64encode(zlib.compress(m.encode("utf-8"),9)),"utf-8")


def dezlibs(m):
    b64 = base64.b64decode(m)
    decompressed = zlib.decompress(b64)
    bytedecode = bytes.decode(decompressed)
    s = str(bytedecode)
    return s
    # return str(bytes.decode(zlib.decompress(base64.b64decode(m))))


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
    return r + "#" + genHashKey(r)


def ups(mpos, mtotal, cpos):
    print("\r字符位置:{}/{}, 对撞位置{}".format(mpos, mtotal, cpos), end="")


def decrypt(msg, key):
    hashedStrLen = 64
    try:
        msg = dezlibs(msg)
    except:
        return "解压缩不正常，请检查消息完整性"
    try:
        hashedKey = msg.split("#")[1]
        msg = msg.split("#")[0]
        if genHashKey(msg) != hashedKey:
            raise RuntimeError()
    except:
        return "解压缩正常，但消息完整性检查失败，请检查消息是否遭到篡改"
    realLen = len(msg) / hashedStrLen
    if realLen % 1 != 0:
        print("消息为: " + msg)
        return "解密失败，消息大小不正确，请检查消息完整性"
    msgList = []
    for i in range(int(realLen)):
        ii = i * hashedStrLen
        a = msg[ii:ii + hashedStrLen]
        msgList.append(a)
    # print("原文共 " + str(len(msgList)) + " 个字符")
    result = ""
    mpos = 0
    for j in msgList:
        mpos += 1
        b = clash(mpos, len(msgList), j, key)
        if (b == False):
            return "解密失败，块{}: {}对撞无结果！请检查密钥！".format(mpos, zlibs(j))
        result += b
        key = genHashKey(result)
    return result


def clash(mpos, mtotal, h, k):
    for i in range(1114111):
        ups(mpos, mtotal, i);
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
            startTime = time.time()
            print(zlibs(encrypt(msg, key)))
            print("耗时:" + str(time.time() - startTime))
        elif (mode == "2"):
            print("执行解密:")
            startTime = time.time()
            print(decrypt(msg, key))
            print("耗时:" + str(time.time() - startTime))
        elif (mode == "3"):
            key = input("请输入密钥:\n")
            print("密钥修改完成")
        elif (mode == "4"):
            exit(0)
        else:
            print("输入有误，请重新输入")
    print("\n")


if __name__ == '__main__':
    main()
