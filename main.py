#  Copyright (c) 2020. Zhangzhe
#  https://home.asec01.net/

import hashlib
import hmac
import zlib
import base64
import time
import pyperclip


# 字符串压缩
def zlibs(m):
    ec = m.encode("utf-8")
    ziped = zlib.compress(ec, 9)
    b64 = base64.b64encode(ziped)
    s = str(b64, "utf-8")
    return s
    # return str(base64.b64encode(zlib.compress(m.encode("utf-8"),9)),"utf-8")


# 字符串解压
def dezlibs(m):
    b64 = base64.b64decode(m)
    decompressed = zlib.decompress(b64)
    bytedecode = bytes.decode(decompressed)
    s = str(bytedecode)
    return s
    # return str(bytes.decode(zlib.decompress(base64.b64decode(m))))


# 加密消息用的哈希函数
def genHmac(m, k):
    message = m.encode('utf-8')
    key = k.encode('utf-8')
    h = hmac.new(key, message, digestmod="sha3_256")
    return h.hexdigest()


# 生成分组密码和校验码的哈希函数
def genHashKey(k, m):
    return genHmac(m, k)
    # return genHash(k + m)

def genHash(m):
    return hashlib.sha3_512((m).encode('utf-8')).hexdigest()

# 加密函数
def encrypt(msg, key):
    r = ""
    aa = ""
    # 保存原始密钥
    orikey = key
    key = genHash(key)
    # 逐个字符加密
    for a in msg:
        # 不是第一个字符的时候使用前面已加密字符的哈希值作为密钥
        if aa != "":
            key = genHashKey(orikey, aa)
        # 计算当前字符的加密结果
        r += genHmac(a, key)
        # 将已加密字符放入变量
        aa += a
    return r + "#" + genHash(r)


# 输出解密进度
def ups(mpos, mtotal, cpos):
    print("\r字符位置:{}/{}, 对撞位置{}".format(mpos, mtotal, cpos), end="")


# 解密函数
def decrypt(msg, key):
    # 尝试解压缩消息
    try:
        msg = dezlibs(msg)
    except:
        return "解压缩不正常，请检查消息完整性"
    # 分离消息与校验码
    try:
        hashedKey = msg.split("#")[1]
        msg = msg.split("#")[0]
        # 消息校验码不匹配
        if genHash(msg) != hashedKey:
            raise Exception()
    except:
        # 消息校验码不匹配或不存在
        return "解压缩正常，但消息完整性检查失败，请检查消息是否遭到篡改"
    # 定义哈希结果长度
    hashedStrLen = 64
    # 计算消息真实长度
    realLen = len(msg) / hashedStrLen
    # 真实长度不为整数时
    if realLen % 1 != 0:
        return "解密失败，消息大小不正确，请检查消息完整性"

    msgList = []
    # 切割密文
    for i in range(int(realLen)):
        ii = i * hashedStrLen
        a = msg[ii:ii + hashedStrLen]
        msgList.append(a)
    # print("原文共 " + str(len(msgList)) + " 个字符")
    result = ""
    mpos = 0
    # 保存原始密钥
    orikey = key
    key = genHash(key)
    # 遍历密文列表
    for j in msgList:
        mpos += 1
        b = clash(mpos, len(msgList), j, key)
        if (b == False):
            return "\r解密失败，块{}: {} 对撞无结果！请检查密钥！".format(mpos, zlibs(j))
        result += b
        key = genHashKey(orikey, result)
    # 解密结果复制到剪贴板
    pyperclip.copy(result)
    return "\r解密结果:\n" + result + "\n解密结果已复制到剪贴板"


# 对撞函数
def clash(mpos, mtotal, h, k):
    # https://www.runoob.com/python3/python3-func-chr-html.html
    for i in range(1114111):
        ups(mpos, mtotal, i)
        try:
            # 计算结果
            a = genHmac(chr(i), k)
            # 若结果匹配
            if a == h:
                # 返回结果
                return chr(i)
        except UnicodeEncodeError:
            # 忽略 UnicodeEncodeError
            pass
    # 无匹配返回False
    return False


# 定义全局变量Key
key = ""

# 主函数
if __name__ == '__main__':
    key = input("请输入密钥:\n")
    while True:
        msg = input("请输入消息:\n")
        mode = input("请选择模式:\n1.加密\n2.解密\n3.修改密钥\n4.退出\n")
        if (mode == "1"):
            print("加密结果:")
            startTime = time.time()
            cryptedText = zlibs(encrypt(msg, key))
            print(cryptedText)
            pyperclip.copy(cryptedText)
            print("密文已复制到剪贴板")
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
