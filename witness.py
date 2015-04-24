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


def check_host(currentip, condition):
    import OpenSSL
    import socket
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.settimeout(1)
    connection = OpenSSL.SSL.Connection(context, socket)
    context.set_timeout(1)
    connection.set_tlsext_host_name(condition["host"].encode())
    try:
        connection.connect(
            (str(currentip), int(condition["port"])))
    except KeyboardInterrupt:
        exit()
    except:
        return "Error"
    connection.setblocking(True)
    try:
        connection.do_handshake()
    except KeyboardInterrupt:
        exit()
    except OpenSSL.SSL.WantReadError:
        return "Timeout"
    except:
        return "Error"
    cert = connection.get_peer_certificate()
    certname = OpenSSL.crypto.X509Name(cert.get_subject())
    try:
        connection.shutdown()
        connection.close()
    except:
        try:
            connection.close()
        except KeyboardInterrupt:
            exit()
        except Exception as e:
            return "Error"
    return certname.commonName


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
        print(condition)
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
                with multiprocessing.Pool(1) as pool:
                    process = pool.apply_async(
                        check_host, [currentip, condition])
                    try:
                        result = process.get(timeout=2)
                    except:
                        print(str(currentip) + " Timeout")
                        continue
                    if result in ["Error", "Timeout"]:
                        print(str(currentip) + " " + result)
                    else:
                        if result.find(
                         condition["common_name_has"]) != -1:
                            print(str(currentip) + " True, CN=" + result)
                            with open(writefilepath, "a+") as writefile:
                                writefile.write(str(currentip) + "\n")
                        else:
                            print(str(currentip) + " False, CN=" + result)

            target = readfile.readline()

if __name__ == "__main__":
    main()
    print("Finished!")
