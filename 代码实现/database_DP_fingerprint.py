import math
import csv
import hmac
import hashlib
import random

# 生成指纹数据库
import numpy as np


def generate_fingerprinted_database(o_database, f_database, K, p, fingerprint, secret_key):
    # 嵌入指纹
    first_attr = 3
    last_attr = 14
    count = 0  # 计数器
    for attr in range(first_attr, last_attr):
        for row in range(len(o_database[0])):
            K = min(K, len(bin(o_database[attr][row])[2:]))
            for k in range(K):
                pmy = bin(o_database[0][row])[2:] + bin(o_database[1][row])[2:] + bin(o_database[2][row])[2:]  # 取前三列为主键
                s = int((pmy + bin(row)[2:] + bin(k)[2:]), 2) + int.from_bytes(secret_key, byteorder='big',
                                                                               signed=False)
                # 产生伪随机数
                random.seed(s)
                u1 = random.randrange(math.floor(1 / (2 * p)) + 1)
                u2 = random.randrange(2)
                u3 = random.randrange(256)

                if u1 % math.floor(1 / (2 * p)) == 0:
                    if u2 == 1:
                        x = 0
                    else:
                        x = 1
                    l = u3 % len(fingerprint)
                    f = fingerprint[l]
                    B = x ^ int(f)
                    f_database[attr][row] = insert_fingerprint(o_database[attr][row], B, k, K)
                    count = count + 1

    print("COUNT:", count)


# 嵌入指纹位
def insert_fingerprint(r, B, k, K):
    r_list = list(bin(int(r))[2:])
    length = len(r_list)
    r_list[length - K + k] = str(int(r_list[length - K + k], 2) ^ B)
    r_dex = int(''.join(r_list), 2)
    return r_dex


# 还原标志位B
def get_B(f_num, r, k, K):
    f_str = bin(f_num)[2:]
    r_str = bin(r)[2:]
    length = len(f_str)

    return int(f_str[length - K + k]) ^ int(r_str[length - K + k])


# 提取指纹
def extract_fingerprint(f_database, o_database, K, p, secret_key, L):
    c0 = []
    c1 = []
    fingerprint = []
    for i in range(L):
        c0.append(0)
        c1.append(0)
        fingerprint.append('?')

    first_attr = 3
    last_attr = 14
    count = 0  # 计数器

    for attr in range(first_attr, last_attr):
        for row in range(len(f_database[0])):
            K = min(K, len(bin(f_database[attr][row])[2:]))
            for k in range(K):
                pmy = bin(f_database[0][row])[2:] + bin(f_database[1][row])[2:] + bin(f_database[2][row])[2:]  # 取前三列为主键
                s = int((pmy + bin(row)[2:] + bin(k)[2:]), 2) + int.from_bytes(secret_key, byteorder='big',
                                                                               signed=False)
                # 产生伪随机数
                random.seed(s)
                u1 = random.randrange(math.floor(1 / (2 * p)) + 1)
                u2 = random.randrange(2)
                u3 = random.randrange(256)

                if u1 % math.floor(1 / (2 * p)) == 0:
                    if u2 == 1:
                        x = 0
                    else:
                        x = 1
                    l = u3 % L
                    B = get_B(f_database[attr][row], o_database[attr][row], k, K)
                    f = B ^ x
                    if f == 1:
                        c1[l] = c1[l] + 1
                    else:
                        c0[l] = c0[l] + 1

                    count = count + 1

    # 采用投票机制还原指纹
    for index in range(L):
        if c1[index] > c0[index]:
            fingerprint[index] = '1'
        elif c1[index] < c0[index]:
            fingerprint[index] = '0'

    return ''.join(fingerprint)


def generate_fingerprint(secret_key, c_round, count):
    # 生成ID_internal
    id_internal = generate_id_internal(c_round, count)

    # 生成指纹串
    hash_function = hashlib.sha256  # 选择散列函数(SHA-256)
    hmac_object = hmac.new(secret_key + id_internal, digestmod=hash_function)
    fingerprint = hmac_object.digest()

    fingerprint = bin(int.from_bytes(fingerprint, byteorder='big', signed=False))[2:]  # 将字节串转为二进制串
    while len(fingerprint) < 256:
        fingerprint += '0'

    return fingerprint


# 生成ID_internal
def generate_id_internal(count, i):
    generate_hash = hashlib.md5()
    generate_hash.update((bin(count)[2:] + bin(i)[2:]).encode("utf-8"))
    id_internal = generate_hash.digest()

    return id_internal


# 计算指纹密度
def fingerprint_density(origin_database, fingerprinted_database):
    result = 0
    for attr in range(len(origin_database)):
        for row in range(len(origin_database[0])):
            result += fingerprinted_database[attr][row] - origin_database[attr][row]
    return result


# 利用numpy的随机数模块来生成拉普拉斯随机数作为噪音
def generate_laplace(sigma):
    return np.random.laplace(loc=0, scale=sigma)


def main():
    origin_database = []
    fingerprinted_database = []

    # 预设参数
    esp = 10  # 隐私预算
    esp_2 = 1
    esp_3 = 1
    delta = 5  # Sensitivity of a relational database，关系数据库敏感度
    secret_key = b'PrivacyPreservingDatabaseFingerprinting'  # 数据库所有者私钥
    L = 256  # 指纹长度
    C = 1  # SP个数
    threshold = 2500

    # 计算相关参数
    K = math.floor(math.log2(delta))
    p = 1 / (math.exp(esp / K) + 1)  # Bernoulli distribution parameter，伯努利参数

    # 导入数据库
    for i in range(14):
        origin_database.append([])
        fingerprinted_database.append([])

    with open('Datasets/adult.csv', 'rt') as csvfile:
        reader = csv.reader(csvfile)
        for attr in reader:
            try:
                for i in range(14):
                    origin_database[i].append(int(attr[i]))
                    fingerprinted_database[i].append(int(attr[i]))
            except ValueError as e:
                continue
            except IndexError as e:
                continue

    # 为C个SP分发指纹数据库
    for c_round in range(C):
        # 参数初始化
        f_density = 0
        count = 0
        lap_noise_1 = 0
        lap_noise_2 = 0
        fingerprint = ''

        # 验证指纹密度是否大于阈值
        while f_density + lap_noise_1 < threshold + lap_noise_2:
            count += 1
            fingerprint = generate_fingerprint(secret_key, c_round, count)  # 生成指纹比特串
            print("insert fingerprint:", fingerprint)
            print("length_f:", len(fingerprint))

            generate_fingerprinted_database(origin_database, fingerprinted_database, K, p, fingerprint,
                                            secret_key)  # 生成指纹数据库
            f_density = fingerprint_density(origin_database, fingerprinted_database)
            print("fingerprint density :", f_density)

            lap_noise_1 = generate_laplace(delta / esp_2)
            lap_noise_2 = generate_laplace(delta / esp_3)
            print("lap_noise_1:", lap_noise_1)
            print("lap_noise_2:", lap_noise_2)

        e_fingerprint = extract_fingerprint(fingerprinted_database, origin_database, K, p, secret_key, L)  # 提取指纹
        print("extract fingerprint:", e_fingerprint)
        print("length_e:", len(e_fingerprint))

        match = 0
        for index in range(L):
            if fingerprint[index] == e_fingerprint[index]:
                match = match + 1
        print("matching rate:", match / L)


main()
