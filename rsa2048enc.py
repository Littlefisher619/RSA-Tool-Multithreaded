import rsa, sys, base64
from multiprocessing import Pool
import threading
import time, signal

'''
def rsa_encrypt(biz_content, public_key, filename):
    _p = rsa.PublicKey.load_pkcs1_openssl_pem(public_key)
    #biz_content = biz_content.encode('utf-8')
    # 2048bit key
    default_encrypt_length = 245
    len_content = len(biz_content)
    if len_content < default_encrypt_length:
        #return base64.b64encode(rsa.encrypt(biz_content, _p))
        return rsa.encrypt(biz_content, _p)
    offset = 0
    params_lst = []
    while len_content - offset > 0:
        print("Encrypted: %.2f%% (%s/%s)"% (offset/len_content*100,offset,len_content))
        if len_content - offset > default_encrypt_length:
            params_lst.append(rsa.encrypt(biz_content[offset:offset+default_encrypt_length], _p))
        else:
            params_lst.append(rsa.encrypt(biz_content[offset:], _p))
        offset += default_encrypt_length
    print("Encryption finished! Exporting...")
    target = b''.join(params_lst)
    return target#base64.b64encode(target)

def rsa_decrypt(biz_content, private_key):
    _pri = rsa.PrivateKey._load_pkcs1_pem(private_key)
    #biz_content = base64.b64decode(biz_content)
    # 2048bit key
    default_length = 256
    len_content = len(biz_content)
    if len_content < default_length:
        return rsa.decrypt(biz_content, _pri)
    offset = 0
    params_lst = []
    while len_content - offset > 0:
        print("Decrypted: %.2f%% (%s/%s)"% (offset/len_content*100,offset,len_content))
        if len_content - offset > default_length:
            params_lst.append(rsa.decrypt(biz_content[offset: offset+default_length], _pri))
        else:
            params_lst.append(rsa.decrypt(biz_content[offset:], _pri))
        offset += default_length
    print("Decryption finished! Exporting...")

    target = b''.join(params_lst)
    return target
'''
encrypteddata = []
decrypteddata = []
tasklen = 0
progress = 0


def rsa_encrypt_task(contendid, data, _p):
    return (contendid, rsa.encrypt(data, _p))


def rsa_encrypt_task_callback(result):
    global enrypteddata, progress
    progress += 1
    print("Encrypted %.2f%% (%s/%s)" % (progress / tasklen * 100, progress, tasklen))
    encrypteddata[result[0]] = result[1]


def rsa_decrypt_task(contendid, data, _pri):
    return (contendid, rsa.decrypt(data, _pri))


def rsa_decrypt_task_callback(result):
    global decrypteddata, progress
    progress += 1
    print("Decrypted %.2f%% (%s/%s)" % (progress / tasklen * 100, progress, tasklen))
    decrypteddata[result[0]] = result[1]


def initializer():
    """Ignore CTRL+C in the worker process."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def rsa_encrypt_multithreaded(biz_content, public_key, filename):
    pool = Pool(16, initializer=initializer)
    _p = rsa.PublicKey.load_pkcs1_openssl_pem(public_key)
    default_encrypt_length = 245
    len_content = len(biz_content)
    if len_content < default_encrypt_length:
        # return base64.b64encode(rsa.encrypt(biz_content, _p))
        return rsa.encrypt(biz_content, _p)
    offset = 0
    global tasklen, encrypteddata
    tasklen = int((len_content + default_encrypt_length - 1) / default_encrypt_length)
    encrypteddata = [b''] * tasklen


    contentid = 0
    while len_content - offset > 0:
        if len_content - offset > default_encrypt_length:
            pool.apply_async(func=rsa_encrypt_task,
                             args=(contentid, biz_content[offset: offset + default_encrypt_length], _p),
                             callback=rsa_encrypt_task_callback)
        else:
            pool.apply_async(func=rsa_encrypt_task, args=(contentid, biz_content[offset:], _p),
                             callback=rsa_encrypt_task_callback)

        offset += default_encrypt_length
        contentid += 1


    pool.close()
    print("Task all generated! Waiting for encryption...")

    pool.join()
    pool.terminate()
    print("Data encrypted! Sorting...")

    w = open(filename, 'wb')
    for i in range(tasklen):
        w.write(encrypteddata[i])
        print("Writing... %.2d%%" % (i / tasklen * 100))
    w.close()


def rsa_decrypt_multithreaded(biz_content, private_key, filename):
    pool = Pool(16, initializer=initializer)
    _pri = rsa.PrivateKey._load_pkcs1_pem(private_key)

    # 2048bit key

    default_length = 256
    len_content = len(biz_content)
    if len_content < default_length:
        return rsa.decrypt(biz_content, _pri)
    offset = 0
    global tasklen, decrypteddata
    tasklen = int((len_content + default_length - 1) / default_length)
    decrypteddata = [b''] * tasklen

    contentid = 0
    while len_content - offset > 0:
        if len_content - offset > default_length:
            pool.apply_async(func=rsa_decrypt_task,
                             args=(contentid, biz_content[offset: offset + default_length], _pri),
                             callback=rsa_decrypt_task_callback)
        else:
            pool.apply_async(func=rsa_decrypt_task, args=(contentid, biz_content[offset:], _pri),
                             callback=rsa_decrypt_task_callback)

        offset += default_length
        contentid += 1


    pool.close()
    print("Task all generated! Waiting for decryption...")

    pool.join()
    pool.terminate()

    print("Data decrypted!")

    target = b''
    w = open(sys.argv[2] + '.dec', 'wb')
    for i in range(tasklen):
        w.write(decrypteddata[i])
        print("Writing... %.2d%%" % (i / tasklen * 100))
    w.close()


if __name__ == '__main__':

    if sys.argv[1] == 'enc':

        f = open(sys.argv[2], 'rb')

        key = open(sys.argv[3], 'rb')
        t_start = time.time()
        rsa_encrypt_multithreaded(f.read(), key.read().decode('utf-8'), sys.argv[2] + '.rsa2048')
        t_end = time.time()
        print("Done! %.2fs was taken." % (t_end - t_start))
        f.close()
        key.close()
    elif sys.argv[1] == 'dec':
        f = open(sys.argv[2], 'rb')

        key = open(sys.argv[3], 'rb')
        t_start = time.time()
        rsa_decrypt_multithreaded(f.read(), key.read().decode('utf-8'), sys.argv[2] + '.dec')
        t_end = time.time()
        print("Done! %.2fs was taken." % (t_end - t_start))
        f.close()
        key.close()
    else:
        print("Usage: rsa2048enc.py enc|dec file key")
