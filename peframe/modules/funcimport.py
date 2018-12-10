#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2015 Gianni Amato
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ----------------------------------------------------------------------

import json
import pefile

def get(pe):
	array = []
	library = []
	libdict = {}
	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dll = entry.dll
			for imp in entry.imports:
				address = hex(imp.address)
				function = imp.name
				#dll파일이 라이브러리에 없을경우 dll 파일을 라이브러리에 추가
				if dll not in library:
					library.append(dll)
				#library 값에 dll, address와 function에 각 값을 추가
				array.append({"library": dll, "address": address, "function": function})

		#라이브러리에 키값을 리스트형식으로 저장
		for key in library:
			libdict[key] = []
		#라이브러리의 lib 리스트에 item 의 주소,함수를 추가
		for lib in library:
			for item in array:
				if lib == item['library']:
					libdict[lib].append({"address": item['address'], "function": item['function']})
	except:
		pass

	return libdict
