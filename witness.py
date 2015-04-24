#!/usr/bin/env python3
"""
The MIT License (MIT)

Copyright (c) 2015 Futur Solo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


from __future__ import print_function, with_statement
import sys
import ipaddress
import multiprocessing
import multiprocessing.pool
import time
from contextlib import closing


class NoDaemonProcess(multiprocessing.Process):
    def _get_daemon(self):
        return False

    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)


class Pool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess


def do_check(nowip, condition):
    result = False
    import OpenSSL
    import socket
    import re
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.settimeout(1)
    connection = OpenSSL.SSL.Connection(context, socket)
    if condition["sni"]:
        connection.set_tlsext_host_name(condition["host"])
    try:
        connection.connect(
            (nowip, condition["port"]))
    except KeyboardInterrupt:
        exit()
    except:
        print(nowip + " Error")
        return
    connection.setblocking(True)
    try:
        connection.do_handshake()
    except KeyboardInterrupt:
        exit()
    except OpenSSL.SSL.WantReadError:
        print(nowip + " Timeout")
        return
    except:
        print(nowip + " Error")
        return
    cert = connection.get_peer_certificate()
    data = []
    for no in range(0, cert.get_extension_count()):
        if cert.get_extension(no).get_short_name() != b"subjectAltName":
            continue
        data = re.sub(
            r"\\[\s\S]", "#",
            re.sub(
                r"\\x[0-9a-zA-Z]{2}", "#",
                (str(cert.get_extension(no).get_data())
                    .replace(r"b\"", "").replace("\"", "")
                    .replace(r"b'", "")
                    .replace(r"'", "").replace("\\\\", "\\")))).split("#")
        for item in data:
            if item != "" and item != "0":
                if item.find(condition["common_name_has"]) != -1:
                    print(nowip + " True, DNS Name=" + item)
                    result = True
                else:
                    print(nowip + " False, DNS Name=" + item)
    if len(data) == 0:
        certname = OpenSSL.crypto.X509Name(cert.get_subject())
        if certname.commonName.find(condition["common_name_has"]) != -1:
            print(nowip + " True, CN=" + certname.commonName)
            result = True
        else:
            print(nowip + " False, CN=" + certname.commonName)
    return result


def check_host(nowip, condition, writefilepath):
    import multiprocessing

    with multiprocessing.Pool(1) as child_pool:
        child_process = child_pool.apply_async(
            do_check, [nowip, condition])
        try:
            result = child_process.get(timeout=3)
        except Exception as e:
            print(e)
            print(nowip + " Timeout")
        if result:
            with open(writefilepath, "a+") as writefile:
                writefile.write(nowip + "\n")


def main():
    readfilepath = sys.argv[1]
    writefilepath = sys.argv[2]

    with open(readfilepath) as readfile:
        target = readfile.readline()
        target = target.replace(" ", "").replace("\n", "").split(",")
        condition = {}
        for item in target:
            condition[item.split(":")[0]] = item.split(":")[1]
        target = readfile.readline()
        condition["sni"] = condition.get("sni", "on")
        if condition["sni"].lower() in ["on", "true", "1"]:
            condition["sni"] = True
        else:
            condition["sni"] = False
        condition["host"] = condition["host"].encode()
        condition["port"] = int(condition["port"])
        condition["process_num"] = int(condition.get("process_num", 1))
        print(condition)
        with closing(Pool(condition["process_num"])) as pool:
            while target:
                target = target.replace(" ", "").replace("\n", "").split("-")
                startip = ipaddress.ip_address(target[0])
                if len(target) > 1:
                    finiship = ipaddress.ip_address(target[1])
                else:
                    finiship = ipaddress.ip_address(target[0])
                currentip = startip - 1
                while currentip < finiship:
                    currentip = currentip + 1
                    nowip = str(currentip)
                    process = pool.apply_async(
                        check_host, [nowip, condition, writefilepath])
                target = readfile.readline()
            pool.close()
            pool.join()

if __name__ == "__main__":
    start_time = time.time()
    main()
    time_range = time.time() - start_time
    print("Finished! Time Used: %.4fs!" % time_range)
