# -*- coding: utf-8 -*-
"""
magic is a wrapper around the libmagic file identification library.

See README for more information.

Usage:

>>> import magic
>>> magic.from_file("testdata/test.pdf")
'PDF document, version 1.2'
>>> magic.from_file("testdata/test.pdf", mime=True)
'application/pdf'
>>> magic.from_buffer(open("testdata/test.pdf").read(1024))
'PDF document, version 1.2'
>>>


"""

import sys
import glob
import os.path
import ctypes
import ctypes.util
import threading

from ctypes import c_char_p, c_int, c_size_t, c_void_p

class MagicException(Exception): pass

class Magic:
    """
    Magic is a wrapper around the libmagic C library.

    """

    def __init__(self, mime=False, magic_file=None, mime_encoding=False,
                 keep_going=False, uncompress=False):
        """
        Create a new libmagic wrapper.

        mime - 값이 True면, mimetypes이 textual descriptions을 대신해 반환
        mime_encoding - True면, codec 반환
        magic_file - 시스템 기본값 대신 mime database 사용
        uncompress - 압축파일 uncompress
        """
        self.flags = MAGIC_NONE
        if mime:
            self.flags |= MAGIC_MIME
        elif mime_encoding:
            self.flags |= MAGIC_MIME_ENCODING
        if keep_going:
            self.flags |= MAGIC_CONTINUE

        if uncompress:
            self.flags |= MAGIC_COMPRESS

        self.cookie = magic_open(self.flags)
        self.lock = threading.Lock()

        magic_load(self.cookie, magic_file)

    def from_buffer(self, buf):
        #`buf`의 내용물을 확인 및 리턴
        with self.lock:
            try:
                return magic_buffer(self.cookie, buf)
            except MagicException as e:
                return self._handle509Bug(e)

    def from_file(self, filename):
        #`filename`의 내용물을 확인
        #파일이 존재하지 않으면, IOError 발생
        if not os.path.exists(filename):
            raise IOError("File does not exist: " + filename)
        with self.lock:
            try:
                return magic_file(self.cookie, filename)
            except MagicException as e:
                return self._handle509Bug(e)

    def _handle509Bug(self, e):
        #e의 message 값이 없고, self의 flags 와 MAGIC_MIME 값이 같으면 application/octet-stream을 리턴
        if e.message is None and (self.flags & MAGIC_MIME):
            return "application/octet-stream"

    def __del__(self):
        # 두 값이 같으면 close하고, cookie값은 초기화
        if self.cookie and magic_close:
            magic_close(self.cookie)
            self.cookie = None

_instances = {}

def _get_magic_type(mime):
    i = _instances.get(mime)
    if i is None:
        i = _instances[mime] = Magic(mime=mime)
    return i

def from_file(filename, mime=False):
    #filname의 파일형식을 리턴, 리턴 value = mimetype
    m = _get_magic_type(mime)
    return m.from_file(filename)

def from_buffer(buffer, mime=False):
    #2진법 string의 파일타입을 리턴, 리턴 value = mimetype
    m = _get_magic_type(mime)
    return m.from_buffer(buffer)




libmagic = None
# libmagic 파일을 아래 셋중에 하나로 찾아서 dll파일에 저장. 만약 libmagic 파일이 없다면 Error 출력
dll = ctypes.util.find_library('magic') or ctypes.util.find_library('magic1') or ctypes.util.find_library('cygmagic-1')

if dll:
    libmagic = ctypes.CDLL(dll)

if not libmagic or not libmagic._name:
    windows_dlls = ['magic1.dll','cygmagic-1.dll']
    platform_to_lib = {'darwin': ['/opt/local/lib/libmagic.dylib',
                                  '/usr/local/lib/libmagic.dylib'] +
                         # Assumes there will only be one version installed
                         glob.glob('/usr/local/Cellar/libmagic/*/lib/libmagic.dylib'),
                       'win32': windows_dlls,
                       'cygwin': windows_dlls }
    for dll in platform_to_lib.get(sys.platform, []):
        try:
            libmagic = ctypes.CDLL(dll)
            break
        except OSError:
            pass

if not libmagic or not libmagic._name:
    raise ImportError('failed to find libmagic.  Check your installation')

magic_t = ctypes.c_void_p
#에러 체크 ( 에러가 없을 경우)
def errorcheck_null(result, func, args):
    if result is None:
        err = magic_error(args[0])
        raise MagicException(err)
    else:
        return result
#에러 체크 (에러가 있을경우)
def errorcheck_negative_one(result, func, args):
    if result is -1:
        err = magic_error(args[0])
        raise MagicException(err)
    else:
        return result

# 파일 이름 리턴 함수
def coerce_filename(filename):
    if filename is None:
        return None
    is_unicode = (sys.version_info[0] <= 2 and
                  isinstance(filename, unicode)) or \
                  (sys.version_info[0] >= 3 and
                   isinstance(filename, str))
    if is_unicode:
        return filename.encode('utf-8')
    else:
        return filename

magic_open = libmagic.magic_open
magic_open.restype = magic_t
magic_open.argtypes = [c_int]

magic_close = libmagic.magic_close
magic_close.restype = None
magic_close.argtypes = [magic_t]

magic_error = libmagic.magic_error
magic_error.restype = c_char_p
magic_error.argtypes = [magic_t]

magic_errno = libmagic.magic_errno
magic_errno.restype = c_int
magic_errno.argtypes = [magic_t]

_magic_file = libmagic.magic_file
_magic_file.restype = c_char_p
_magic_file.argtypes = [magic_t, c_char_p]
_magic_file.errcheck = errorcheck_null

def magic_file(cookie, filename):
    return _magic_file(cookie, coerce_filename(filename))

_magic_buffer = libmagic.magic_buffer
_magic_buffer.restype = c_char_p
_magic_buffer.argtypes = [magic_t, c_void_p, c_size_t]
_magic_buffer.errcheck = errorcheck_null

def magic_buffer(cookie, buf):
    return _magic_buffer(cookie, buf, len(buf))


_magic_load = libmagic.magic_load
_magic_load.restype = c_int
_magic_load.argtypes = [magic_t, c_char_p]
_magic_load.errcheck = errorcheck_negative_one

def magic_load(cookie, filename):
    return _magic_load(cookie, coerce_filename(filename))

magic_setflags = libmagic.magic_setflags
magic_setflags.restype = c_int
magic_setflags.argtypes = [magic_t, c_int]

magic_check = libmagic.magic_check
magic_check.restype = c_int
magic_check.argtypes = [magic_t, c_char_p]

magic_compile = libmagic.magic_compile
magic_compile.restype = c_int
magic_compile.argtypes = [magic_t, c_char_p]



MAGIC_NONE = 0x000000 # No flags
MAGIC_DEBUG = 0x000001 # Turn on debugging
MAGIC_SYMLINK = 0x000002 # Follow symlinks
MAGIC_COMPRESS = 0x000004 # Check inside compressed files
MAGIC_DEVICES = 0x000008 # Look at the contents of devices
MAGIC_MIME = 0x000010 # Return a mime string
MAGIC_MIME_ENCODING = 0x000400 # Return the MIME encoding
MAGIC_CONTINUE = 0x000020 # Return all matches
MAGIC_CHECK = 0x000040 # Print warnings to stderr
MAGIC_PRESERVE_ATIME = 0x000080 # Restore access time on exit
MAGIC_RAW = 0x000100 # Don't translate unprintable chars
MAGIC_ERROR = 0x000200 # Handle ENOENT etc as real errors

MAGIC_NO_CHECK_COMPRESS = 0x001000 # Don't check for compressed files
MAGIC_NO_CHECK_TAR = 0x002000 # Don't check for tar files
MAGIC_NO_CHECK_SOFT = 0x004000 # Don't check magic entries
MAGIC_NO_CHECK_APPTYPE = 0x008000 # Don't check application type
MAGIC_NO_CHECK_ELF = 0x010000 # Don't check for elf details
MAGIC_NO_CHECK_ASCII = 0x020000 # Don't check for ascii files
MAGIC_NO_CHECK_TROFF = 0x040000 # Don't check ascii/troff
MAGIC_NO_CHECK_FORTRAN = 0x080000 # Don't check ascii/fortran
MAGIC_NO_CHECK_TOKENS = 0x100000 # Don't check ascii/tokens
