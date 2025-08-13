#!/usr/bin/python3
from ctypes import CDLL, c_int, c_uint

lib = CDLL("libc.so.6")
lib.srand(lib.time(0))

arr = (c_int * 6)(121,1231231,20312312,122342342,90988878,4294967266)

for i in range(6):
    arr[i] -= lib.rand() % 10 - 1

s = sum(arr)
print(s)
