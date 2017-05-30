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
import os
import sys


from epiphyte import Epiphyte


try:
    import pytest
except ImportError:
    sys.exit("Requires pytest module")


class TestEpiphyte:
    """
    Epiphyte unit tests.
    """
    def test_fuzzy(self):
        """
        Fuzzy data tests.
        """
        thread = os.urandom(32)
        chunks = [os.urandom(2 ** n) for n in range(8)]

        epiphyte = Epiphyte(thread, b'[PYTEST]')

        for chunk in chunks:
            epiphyte.append(chunk)

        epiphyte = Epiphyte(thread, b'[PYTEST]')

        for chunk, data in zip(chunks, epiphyte):
            assert chunk == data


if __name__ == "__main__":
    sys.exit(pytest.main(list(sys.argv)))
