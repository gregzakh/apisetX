# -*- coding: utf-8 -*-
from ctypes  import cast, c_void_p, c_wchar_p
from os.path import join as combine
from pathlib import Path
from struct  import unpack
from winreg  import HKEY_LOCAL_MACHINE, OpenKey, EnumKey, QueryInfoKey, QueryValueEx

def getsystempath() -> str:
   return combine(cast(c_void_p(0x7FFE0030), c_wchar_p).value, 'system32')

def getextensionslist():
   point = r'SYSTEM\CurrentControlSet\Control\Session Manager\ApiSetSchemaExtensions'
   syspath = getsystempath() # instead of windll.kernelbase.GetSystemDirectoryW
   with OpenKey(HKEY_LOCAL_MACHINE, point) as topkey:
      for key in range(QueryInfoKey(topkey)[0]):
         with OpenKey(topkey, EnumKey(topkey, key)) as subkey:
            dllname = QueryValueEx(subkey, 'FileName')[0]
            print(dllname)
            ImageHelper(combine(syspath, dllname)).readschema()

class ImageHelper(object):
   def __init__(self, path):
      self.__buf = Path(path).read_bytes()
   def __getchunk(self, offset : int, read : int) -> bytes:
      return self.__buf[offset:offset+read]
   def __getapisetblock(self) -> None: # without basic PE checks
      mov = int.from_bytes(self.__getchunk(0x3C, 0x04), 'little') + 0x04
      ifh = unpack('<2H3L2H', self.__getchunk(mov, 0x14)) # IMAGE_FILE_HEADER
      mov += ifh[5] + 0x14 # look for .apiset section
      for _ in range(ifh[1]):
         sec = unpack('<8s6L2HL', self.__getchunk(mov, 0x28))
         if b'.apiset\x00' == sec[0]:
            self.__buf = self.__getchunk(sec[4], sec[3])
            break
         mov += 0x28 # next IMAGE_SECTION_HEADER
   def readschema(self) -> None:
      self.__getapisetblock() # reduce buffer size
      mov = 0 # cursor (points to start now)
      top = unpack('<7L', self.__getchunk(mov, 0x1C)) # API_SET_NAMESPACE
      mov += 0x1C # sizeof(API_SET_NAMESPACE)
      for _ in range(top[3]):
         entry = unpack('<6L', self.__getchunk(mov, 0x18))
         print(f"\t{str(self.__getchunk(entry[1], entry[2]), 'utf-8')}")
         tmp = entry[4] # values cursor
         for _ in range(entry[5]):
            value = unpack('<5L', self.__getchunk(tmp, 0x14))
            print(f"\t\t{str(self.__getchunk(value[3], value[4]), 'utf-8')}")
            tmp += 0x14 # sizeof(API_SET_VALUE_ENTRY)
         mov += 0x18 # sizeof(API_SET_NAMESPACE_ENTRY)
      print('\n\n')

if __name__ == '__main__':
   getextensionslist()
