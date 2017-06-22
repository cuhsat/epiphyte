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
    sys.exit("Requires Requests")


try:
    from Crypto import Random
    from Crypto.Cipher import ChaCha20
    from Crypto.Protocol.KDF import scrypt
except ImportError:
    sys.exit("Requires PyCryptodome")


__all__, __version__ = ["Epiphyte", "String", "TinyUrl" "Uss"], "0.6.1"


class String(object):
    """
    String conversions.
    """
    @staticmethod
    def decode16(data):
        """
        Returns the hexadecimal decoded bytes from a UTF-8 string.
        """
        return binascii.unhexlify(data.encode())

    @staticmethod
    def encode16(data):
        """
        Returns a UTF-8 string from hexadecimal encoded bytes.
        """
        return binascii.hexlify(data).decode()

    @staticmethod
    def decode64(data):
        """
        Returns the URL safe Base64 decoded bytes from a UTF-8 string.
        """
        return base64.urlsafe_b64decode(data.encode())

    @staticmethod
    def encode64(data):
        """
        Returns a UTF-8 string from URL safe Base64 encoded bytes.
        """
        return base64.urlsafe_b64encode(data).decode()

    @staticmethod
    def bytes(data):
        """
        Returns the bytes from a UTF-8 string.
        """
        return data if sys.version_info < (3,) else data.encode()

    @staticmethod
    def utf8(data):
        """
        Returns a UTF-8 string from bytes.
        """
        return data if sys.version_info < (3,) else data.decode()


class Storage(object):
    """
    Abstract key/value storage.
    """
    def __init__(self):
        """
        Not implemented (and never will).
        """
        raise NotImplementedError

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
        response = request("GET", self.get_url + key, allow_redirects=False)

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
        response = request("POST", self.set_url, params={
            "url": "http://127.0.0.1/#" + value,
            "alias": key
        })

        if response.status_code != 200:
            raise Exception("Invalid status")

        if "not available" in response.text.lower():
            raise Exception("Already exists")


class TinyUrl(Storage):
    """
    TinyURL.com storage.
    """
    def __init__(self):
        """
        Initializes the storage.
        """
        self.get_url = "https://tinyurl.com/"
        self.set_url = "https://tinyurl.com/create.php"


class Uss(Storage):
    """
    USS custom storage.
    """
    def __init__(self, server):
        """
        Initializes the storage.
        """
        self.get_url = server + "/"
        self.set_url = server + "/create"


class Chunk(object):
    """
    Data object.
    """
    def __init__(self, link=b"", data=b""):
        """
        Initializes the chunk.
        """
        self.link = link
        self.data = data

    def decrypt(self, key, frame):
        """
        Decrypts the chunk.
        """
        self.frame = frame

        frame = ChaCha20.new(key=key[:32], nonce=key[32:]).decrypt(frame)

        self.link = frame[:20]
        self.data = frame[20:]

    def encrypt(self, key, data):
        """
        Encrypts the chunk.
        """
        self.link = Random.get_random_bytes(20) # Alias max
        self.data = data

        frame = self.link + self.data
        frame = ChaCha20.new(key=key[:32], nonce=key[32:]).encrypt(frame)

        self.frame = frame


class Thread(list):
    """
    List of chunks.
    """
    def __init__(self, thread, salt):
        """
        Initializes the thread.
        """
        self.thread = thread
        self.append(Chunk(self.hash(salt, 20)))

    def __iter__(self):
        """
        Returns an iterator for all chunk data.
        """
        return iter([chunk.data for chunk in self[1:]])

    def last(self):
        """
        Returns the last chunk.
        """
        return self[-1]

    def hash(self, data, length):
        """
        Returns the derived hash.
        """
        return scrypt(data, self.thread, length, 16384, 8, 1, 1)

    def decrypt(self, data):
        """
        Adds a decrypted chunk.
        """
        last = self.last()

        chunk = Chunk()
        chunk.decrypt(self.hash(last.data, 40), data)

        self.append(chunk)

    def encrypt(self, data):
        """
        Adds an encrypted chunk and returns the key/value pair.
        """
        last = self.last()

        chunk = Chunk()
        chunk.encrypt(self.hash(last.data, 40), data)

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
        Returns a thread iterator.
        """
        return iter(self.thread)

    def split(self, message):
        """
        Returns the message parts.
        """
        return [message[i:i + 4096] for i in range(0, len(message), 4096)]

    def follow(self):
        """
        Follows the thread.
        """
        while True:
            chunk = self.thread.last()
            value = self.storage[chunk.link]

            if not value:
                break

            self.thread.decrypt(value)

    def append(self, message):
        """
        Appends a new message to the thread.
        """
        self.follow()

        parts = self.split(message)

        for part in parts:
            key, value = self.thread.encrypt(part)

            self.storage[key] = value


def main(script, thread="--help", *message):
    """
    Usage: %s THREAD [MESSAGE ...]
    """
    try:
        if thread in ("-h", "--help"):
            print(main.__doc__.strip() % os.path.basename(script))

        elif thread in ("-l", "--license"):
            print(__doc__.strip())

        elif thread in ("-v", "--version"):
            print("Epiphyte " + __version__)

        else:
            epiphyte = Epiphyte(String.bytes(thread))

            if message:
                epiphyte.append(String.bytes(" ".join(message) + os.linesep))

            for message in epiphyte:
                sys.stdout.write(String.utf8(message))

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
