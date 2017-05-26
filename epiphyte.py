#!/usr/bin/env python
"""
Copyright (c) 2017 Christian Uhsat <christian@uhsat.de>

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
import base64
import binascii
import os
import re
import sys


try:
    from requests import request
    from requests.exceptions import ConnectionError, Timeout
except ImportError:
    sys.exit("Requires Requests (https://github.com/kennethreitz/requests)")


try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, RIPEMD, SHA256
    from Crypto.Util.py3compat import bchr, bord
except ImportError:
    sys.exit("Requires PyCrypto (https://github.com/dlitz/pycrypto)")


__all__, __version__ = ["Epiphyte"], "0.3.0"


def encode(data): # Compatibility hack
    return data if sys.version_info < (3,) else data.encode()

def decode(data): # Compatibility hack
    return data if sys.version_info < (3,) else data.decode()

def encode16(data): # Utility shortcut
    return binascii.hexlify(data).decode()

def encode64(data): # Utility shortcut
    return base64.urlsafe_b64encode(data).decode()

def decode64(data): # Utility shortcut
    return base64.urlsafe_b64decode(data.encode())


class TinyUrl(object):
    GET_URL = "http://tinyurl.com/"
    SET_URL = "http://tinyurl.com/create.php"

    def __delitem__(self, key):
        raise NotImplementedError

    def __getitem__(self, key):
        return decode64(self.get(encode16(key)))

    def __setitem__(self, key, value):
        self.set(encode16(key), encode64(value))

    def __get(self, key):
        return request("GET", TinyUrl.GET_URL + key, allow_redirects=False)

    def __set(self, key, value):
        return request("POST", TinyUrl.SET_URL, params={
            # "source": "indexpage",
            # "submit": "Make+TinyURL!",
            "url": "http://127.0.0.1#" + value,
            "alias": key
        })

    def get(self, key):
        response = self.__get(key)
        location = response.headers.get("Location", "")

        if response.status_code == 404:
            return "" # Not found

        if response.status_code != 301:
            raise Exception("Invalid status")

        if not "#" in location:
            raise Exception("Invalid header")

        return location.rsplit("#", 1)[-1]

    def set(self, key, value):
        response = self.__set(key, value)

        if response.status_code != 200:
            raise Exception("Invalid status")

        if "not available" in response.text:
            raise Exception("Already exists")


class Chunk(object):
    def __init__(self, link=b"", data=b""):
        self.link = link
        self.data = data

    def __link(self):
        return Random.get_random_bytes(20)

    def __key(self, key):
        return (key[:16], key[16:])

    def __cut(self, data):
        return data[:-bord(data[-1])]

    def __pad(self, data):
        size = AES.block_size - (len(data) % AES.block_size)
        return data + (bchr(size) * size)

    def __decrypt(self, key, data):
        key, iv = self.__key(key)
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    def __encrypt(self, key, data):
        key, iv = self.__key(key)
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    def decrypt(self, key, frame):
        self.frame = frame

        frame = self.__decrypt(key, self.frame)
        frame = self.__cut(frame)

        self.link = frame[:20]
        self.data = frame[20:]

    def encrypt(self, key, data):
        self.link = self.__link()
        self.data = data

        frame = self.__pad(self.link + self.data)
        frame = self.__encrypt(key, frame)

        self.frame = frame


class Thread(list):
    def __init__(self, thread, salt):
        self.thread = thread
        self.append(Chunk(self.__init(salt)))

    def __iter__(self):
        return iter([chunk.data for chunk in self[1:]])

    def __repr__(self):
        return decode(self.thread)

    def __init(self, salt):
        return HMAC.new(salt, self.thread, RIPEMD).digest()

    def __hash(self, data):
        return HMAC.new(data, self.thread, SHA256).digest()

    def last(self):
        return self[-1]

    def decrypt(self, entry):
        last = self.last()

        chunk = Chunk()
        chunk.decrypt(self.__hash(last.data), entry)

        self.append(chunk)

    def encrypt(self, entry):
        last = self.last()

        chunk = Chunk()
        chunk.encrypt(self.__hash(last.data), entry)

        self.append(chunk)

        return (last.link, chunk.frame)


class Epiphyte(Thread):
    def __init__(self, thread, salt=b"epiphyte", provider=TinyUrl()):
        self.thread = Thread(thread, salt)
        self.provider = provider
        self.pull()

    def __iter__(self):
        return iter(self.thread)

    def __repr__(self):
        return repr(self.thread)

    def pull(self):
        while True:
            chunk = self.thread.last()
            frame = self.provider[chunk.link]

            if not frame:
                break

            self.thread.decrypt(frame)

    def push(self, message):
        self.pull()

        link, frame = self.thread.encrypt(message)

        self.provider[link] = frame


def main(script, thread="--help", *message):
    """
    Usage: %s [OPTION|THREAD] [MESSAGE...]

    Options:
      -h, --help      Shows this text
      -l, --license   Shows the license
      -v, --version   Shows the version

    Report bugs to <christian@uhsat.de>
    """
    try:
        script = os.path.basename(script)

        if thread in ("/?", "-h", "--help"):
            print(re.sub("(?m)^ {4}", "", main.__doc__ % script).strip())

        elif thread in ("-l", "--license"):
            print(__doc__.strip())

        elif thread in ("-v", "--version"):
            print("Epiphyte " + __version__)

        else:
            epiphyte = Epiphyte(encode(thread))

            if message:
                epiphyte.push(encode(" ".join(message)))

            for message in epiphyte:
                print(decode(message))

    except KeyboardInterrupt:
        return "Abort"

    except ConnectionError:
        return "Error: Connection failed"

    except Timeout:
        return "Error: Connection timeout"

    except Exception as ex:
        return "Error: %s" % ex


if __name__ == "__main__":
    sys.exit(main(*sys.argv))
