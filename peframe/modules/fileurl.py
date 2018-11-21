#!/usr/bin/env python

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
##파일 내부에서 각종 URL을 추출하는 파일
import re
import json
import string
import stringstat
#유효한 ip검사 유효한 ip가 아니면 False 리턴
def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False
#파일 이름과 string을 받아오는 함수 (파일의 딕셔너리, url과 ip의 리스트,fuzzing의 딕셔너리를 리턴)
def get(filename, strings_match):
	strings_info = json.loads(stringstat.get(filename))
	strings_list = strings_info['content']
	ip_list = []
	file_list = []
	filetype_dict = {}
	url_list = []
	fuzzing_dict = {}
	apialert_list = []
	antidbg_list = []

	# 파일타입을 받아와서 Fuzzing(소프트웨어 있는 버그를 찾음)
	file_type = strings_match['filetype'].items()
	fuzzing_list = strings_match['fuzzing'].items()

	# Strings 분석
	for string in strings_list:
		# URL list
		urllist = re.findall(r'((smb|srm|ssh|ftps?|file|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', string, re.MULTILINE)
		if urllist:
			for url in urllist:
				url_list.append(url[0])

		# IP list
		iplist = re.findall(r'[0-9]+(?:\.[0-9]+){3}', string, re.MULTILINE)
		if iplist:
			for ip in iplist:
				if valid_ip(str(ip)) and not re.findall(r'[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0', str(ip)):
					ip_list.append(str(ip))

		# FILE list
		fname = re.findall("(.+(\.([a-z]{2,3}$)|\/.+\/|\\\.+\\\))+", string, re.IGNORECASE | re.MULTILINE)
		if fname:
			for word in fname:
				word = filter(None, word[0])
				file_list.append(word)

	# Purge list
	ip_list = filter(None, list(set([item for item in ip_list])))
	url_list = filter(None, list(set([item for item in url_list])))

	# Initialize filetype
	for key, value in file_type:
		filetype_dict[key] = []

	# 유효한 파일 찾기
	array_tmp = []
	for file in file_list:
		for key, value in file_type:
			match = re.findall("\\"+value+"$", file, re.IGNORECASE | re.MULTILINE)
			if match and file.lower() not in array_tmp and len(file) > 4:
				filetype_dict[key].append(file)
				array_tmp.append(file.lower())

	# key의 파일타입이 빈경우 삭제
	for key, value in filetype_dict.items():
		if not filetype_dict[key]:
			del filetype_dict[key]

	# fuzzing(버그 찾기)
	for key, value in fuzzing_list:
		fuzzing_dict[key] = []

	# fuzzing 을 위해 스트링 분석
	array_tmp = []
	for string in strings_list:
		for key, value in fuzzing_list:
			fuzz_match = re.findall(value, string, re.IGNORECASE | re.MULTILINE)
			if fuzz_match and string.lower() not in array_tmp:
				fuzzing_dict[key].append(string)
				array_tmp.append(string.lower())

	#빈 키,벨류의 파일타입 삭제
	for key, value in filetype_dict.items():
		if not filetype_dict[key]:
			del filetype_dict[key]

	#빈 key값의 fuzzing 을 삭제
	for key, value in fuzzing_list:
		if not fuzzing_dict[key]:
			del fuzzing_dict[key]

	return {"file":  filetype_dict, "url": url_list, "ip": ip_list, "fuzzing": fuzzing_dict}
