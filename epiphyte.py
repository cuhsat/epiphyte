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
import sys


try:
    from requests import request
    from requests.exceptions import ConnectionError, Timeout
except ImportError:
    sys.exit("Requires requests module")


try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    sys.exit("Requires pycrypto module")


__all__, __version__ = ["Epiphyte"], "0.4.2"


class String(object):
    """
    String encodings.
    """
    @staticmethod
    def decode(data):
        """
        Returns the UTF-8 decoded data.
        """
        return data if sys.version_info < (3,) else data.decode()

    @staticmethod
    def encode(data):
        """
        Returns the UTF-8 encoded data.
        """
        return data if sys.version_info < (3,) else data.encode()

    @staticmethod
    def decode16(data):
        """
        Returns the hexadecimal decoded data.
        """
        return binascii.unhexlify(data.encode())

    @staticmethod
    def encode16(data):
        """
        Returns the hexadecimal encoded data.
        """
        return binascii.hexlify(data).decode()

    @staticmethod
    def decode64(data):
        """
        Returns the URL safe Base64 decoded data.
        """
        return base64.urlsafe_b64decode(data.encode())

    @staticmethod
    def encode64(data):
        """
        Returns the URL safe Base64 encoded data.
        """
        return base64.urlsafe_b64encode(data).decode()


class TinyUrl(object):
    """
    TinyURL key/value storage using the anchor fragment.
    """
    def __init__(self):
        """
        Initializes the internal structures.
        """
        self.GET_URL = "https://tinyurl.com/"
        self.SET_URL = "https://tinyurl.com/create.php"

    def __delitem__(self, key):
        """
        Not implemented (and never will).
        """
        raise NotImplementedError

    def __getitem__(self, key):
        """
        Gets a Base64 decoded value.
        """
        return String.decode64(self.get(String.encode16(key)))

    def __setitem__(self, key, value):
        """
        Sets a Base64 encoded value.
        """
        self.set(String.encode16(key), String.encode64(value))

    def get(self, key):
        """
        Gets a value by the key.
        """
        response = request("GET", self.GET_URL + key, allow_redirects=False)
        location = response.headers.get("Location", "")

        if response.status_code == 404:
            return "" # Not found

        if response.status_code != 301:
            raise Exception("Invalid status")

        if not "#" in location:
            raise Exception("Invalid header")

        return location.rsplit("#", 1)[-1]

    def set(self, key, value):
        """
        Sets a value to the key.
        """
        response = request("POST", self.SET_URL, params={
            "url": "http://127.0.0.1#" + value,
            "alias": key
        })

        if response.status_code != 200:
            raise Exception("Invalid status")

        if "not available" in response.text:
            raise Exception("Already exists")


class Chunk(object):
    """
    Data chunk.
    """
    def __init__(self, link=b"", data=b""):
        """
        Initializes the internal structures.
        """
        self.link = link
        self.data = data

    def decrypt(self, key, frame):
        """
        Decrypts the chunk.
        """
        self.frame = frame

        frame = AES.new(key[:16], AES.MODE_CFB, key[16:]).decrypt(frame)

        self.link = frame[:20]
        self.data = frame[20:]

    def encrypt(self, key, data):
        """
        Encrypts the chunk.
        """
        self.link = Random.get_random_bytes(20)
        self.data = data

        frame = self.link + self.data
        frame = AES.new(key[:16], AES.MODE_CFB, key[16:]).encrypt(frame)

        self.frame = frame


class Thread(list):
    """
    Thread of chunks.
    """
    def __init__(self, thread, salt):
        """
        Initializes the internal structures.
        """
        self.thread = thread
        self.append(Chunk(self.hash(salt, 20)))

    def __iter__(self):
        """
        Returns an iterator for all valid chunks.
        """
        return iter([chunk.data for chunk in self[1:]])

    def last(self):
        """
        Returns the last thread chunk.
        """
        return self[-1]

    def hash(self, data, length):
        """
        Returns the derived hash.
        """
        return PBKDF2(data, self.thread, length)

    def add(self, data):
        """
        Adds a decrypted chunk.
        """
        last = self.last()

        chunk = Chunk()
        chunk.decrypt(self.hash(last.data, 32), data)

        self.append(chunk)

    def new(self, data):
        """
        Adds an encrypted chunk and returns the key/value pair.
        """
        last = self.last()

        chunk = Chunk()
        chunk.encrypt(self.hash(last.data, 32), data)

        self.append(chunk)

        return (last.link, chunk.frame)


class Epiphyte(object):
    """
    The epiphyte protocol.
    """
    def __init__(self, thread, salt=b"epiphyte", storage=TinyUrl()):
        """
        Initializes the protocol.
        """
        self.thread = Thread(thread, salt)
        self.storage = storage
        self.follow()

    def __iter__(self):
        """
        Returns the thread iterator.
        """
        return iter(self.thread)

    def follow(self):
        """
        Follows all new chunks on the thread.
        """
        while True:
            chunk = self.thread.last()
            frame = self.storage[chunk.link]

            if not frame:
                break

            self.thread.add(frame)

    def append(self, message):
        """
        Appends a new chunk to the thread.
        """
        self.follow()

        link, frame = self.thread.new(message)

        self.storage[link] = frame


def main(script, thread="--help", *message):
    """
    Usage: %s THREAD [MESSAGE ...]
    """
    try:
        if thread in ("/?", "-h", "--help"):
            print(main.__doc__.strip() % os.path.basename(script))

        elif thread in ("-l", "--license"):
            print(__doc__.strip())

        elif thread in ("-v", "--version"):
            print("Epiphyte " + __version__)

        else:
            epiphyte = Epiphyte(String.encode(thread))

            if message:
                epiphyte.append(String.encode(" ".join(message)))

            for message in epiphyte:
                print(String.decode(message))

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
