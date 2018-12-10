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

import os
import re
import sys
import json
import hashlib
import time, datetime

from modules import help

from modules import pefile
from modules import peutils
from modules import magic

from modules import xor
from modules import peid
from modules import cert
from modules import apimutex
from modules import antivm
from modules import apiantidbg
from modules import directories

from modules import meta
from modules import fileurl
from modules import apialert

from modules import sections
from modules import directory
from modules import resources
from modules import funcimport
from modules import funcexport
from modules import stringstat
from modules import virustotal


# 파일이 있는지 확인
def isfile(filename):
	if os.path.isfile(filename):
		return True
	else:
		print "No file found."
		exit()

# 파일의 타입 반환
def filetype(filename):
	type = magic.from_file(filename)
	return type

# pe파일의 imphash값 반환
def get_imphash(filename):
	return pe.get_imphash()

# hash 값들을 반환
def get_hash(filename):
	fh = open(filename, 'rb') # 파일 열기
	# md5, sha1, sha256의 값 저장
	m = hashlib.md5()
	s = hashlib.sha1()
	s256 = hashlib.sha256()

	while True:
		data = fh.read(8192) # 8192 바이트만큼 파일을 읽음
		if not data: # data가 없으면 종료
			break
		# md5, sha1, sha256의 값 업데이트
		m.update(data)
		s.update(data)
		s256.update(data)
	# md5, sha1, sha256 설정
	md5  = m.hexdigest()
	sha1 = s.hexdigest()
	sha256 = s256.hexdigest()

	# md5, sha1, sha256 imphash반환
	try:
		ih = get_imphash(filename)
		return md5,sha1,sha256,ih
	except:
		return md5,sha1,sha256

# pe파일의 정보를 반환
def get_pe_fileinfo(pe, filename):
	# is dll?
	dll = pe.FILE_HEADER.IMAGE_FILE_DLL

	# num sections
	nsec = pe.FILE_HEADER.NumberOfSections

	# timestamp
	tstamp = pe.FILE_HEADER.TimeDateStamp
	try:
		""" return date """
		tsdate = datetime.datetime.fromtimestamp(tstamp)
	except:
		""" return timestamp """
		tsdate = str(tstamp) + " [Invalid date]"

	# get md5, sha1, sha256, imphash

	md5, sha1, sha256, imphash = get_hash(filename)
	hash_info = {"md5": md5, "sha1": sha1, "sha256": sha256}

	detected = []

	# directory list
	dirlist = directories.get(pe)

	# digital signature
	for sign in dirlist:
		if sign == "security": detected.append("sign")

	# packer (peid)
	packer = peid.get(pe, userdb)
	if packer: detected.append("packer")

	# mutex
	mutex = apimutex.get(pe, strings_match)
	if mutex: detected.append("mutex")

	# anti debug
	antidbg = apiantidbg.get(pe, strings_match)
	if antidbg: detected.append("antidbg")

	# Xor
	xorcheck = xor.get(filename)
	if xorcheck: detected.append("xor")

	# anti virtual machine
	antivirtualmachine = antivm.get(filename)
	if antivirtualmachine: detected.append("antivm")

	# api alert suspicious
	apialert_info = apialert.get(pe, strings_match)

	# file and url
	fileurl_info = fileurl.get(filename, strings_match)
	file_info = fileurl_info["file"]
	url_info = fileurl_info["url"]
	ip_info = fileurl_info["ip"]
	fuzzing_info = fileurl_info["fuzzing"]

	# meta info
	meta_info = meta.get(pe)

	# import function
	import_function = funcimport.get(pe)

	# export function
	export_function = funcexport.get(pe)

	# sections
	sections_info = sections.get(pe)

	# resources
	resources_info = resources.get(pe)

	# virustotal
	virustotal_info = virustotal.get(md5, strings_match)
	# json으로 반환
	return json.dumps({"peframe_ver": help.VERSION,
						"file_type": ftype,
						"file_name": fname,
						"file_size": fsize,
						"hash": hash_info,
						"file_found": file_info,
						"url_found": url_info,
						"ip_found": ip_info,
						"virustotal": virustotal_info,
						"fuzzing": fuzzing_info,
						"pe_info": {
							"import_hash": imphash,
							"compile_time": str(tsdate),
							"dll": dll,
							"sections_number": nsec,
							"xor_info": xorcheck,
							"detected": detected,
							"directories": dirlist,
							"sign_info": cert.get(pe),
							"packer_info": packer,
							"antidbg_info": apiantidbg.get(pe, strings_match),
							"mutex_info": apimutex.get(pe, strings_match),
							"antivm_info": antivirtualmachine,
							"apialert_info": apialert_info,
							"meta_info": meta_info,
							"import_function": import_function,
							"export_function": export_function,
							"sections_info": sections_info,
							"resources_info": resources_info
							}
						},
						indent=4, separators=(',', ': '))
# 파일의 정보를 반환
def get_fileinfo(filename):
	strings_info = json.loads(stringstat.get(filename))
	all_strings = strings_info["content"]

	# file and url
	fileurl_info = fileurl.get(filename, strings_match)
	file_info = fileurl_info["file"]
	url_info = fileurl_info["url"]
	ip_info = fileurl_info["ip"]
	fuzzing_info = fileurl_info["fuzzing"]

	md5, sha1, sha256 = get_hash(filename)
	hash_info = {"md5": md5, "sha1": sha1, "sha256": sha256}

	# virustotal
	virustotal_info = virustotal.get(md5, strings_match)
	# json으로 반환
	return json.dumps({"peframe_ver": help.VERSION,
						"file_type": ftype,
						"file_name": fname,
						"file_size": fsize,
						"hash": hash_info,
						"file_found": file_info,
						"url_found": url_info,
						"ip_found": ip_info,
						"virustotal": virustotal_info,
						"fuzzing": fuzzing_info,
						"pe_info": False},
						indent=4, separators=(',', ': '))

# 기본출력
def stdoutput(get_info_from):
	output = json.loads(get_info_from)

	print "Peframe v.", output['peframe_ver']
	print
	print "Short information"
	print "-"*60
	print "File type".ljust(15),output['file_type']
	print "File name".ljust(15), output['file_name']
	print "File size".ljust(15), output['file_size']
	print "Hash MD5".ljust(15), output['hash']['md5']

	# output에 virustotal 이 있으면 해당정보 출력
	if output['virustotal']:
		positives = output['virustotal']['positives']
		total = output['virustotal']['total']
		print "Virustotal".ljust(15), str(positives)+'/'+str(total)

	if output['pe_info']:
		for item in output['pe_info']:
			if output['pe_info'][item]:

				if item == 'detected':
					print "Detected".ljust(15), ', '.join(output['pe_info'][item])

				if item == 'directories':
					print "Directories".ljust(15), ', '.join(output['pe_info'][item])
				if item == 'sections_number':
					if output['pe_info'][item] > 0:
						x = 0
						for suspicious in output['pe_info']['sections_info']:
							if suspicious['suspicious']:
								x = x+1
					print "Sections".ljust(15), output['pe_info'][item], '('+str(x)+' suspicious)'

				if item == 'import_hash':
					print "Import Hash".ljust(15), output['pe_info'][item]

				if item == 'compile_time':
					print "Compile time".ljust(15), output['pe_info'][item]

				if item == 'dll':
					print "Dll".ljust(15), output['pe_info'][item]

	if output['pe_info']:
		for item in output['pe_info']:
			if output['pe_info'][item]:

				if item == 'xor_info':
					print
					print "Xor info"
					print "-"*60
					print "Key length".ljust(15), "Offset (hex)".ljust(15), "Offset (dec)"
					for elem in output['pe_info'][item]:
						print elem.ljust(15), hex(output['pe_info'][item][elem]).ljust(15), output['pe_info'][item][elem]

				if item == 'sign_info':
					print
					print "Sign info"
					print "-"*60
					for elem in output['pe_info'][item]:
						print elem.ljust(15), output['pe_info'][item][elem]

				if item == 'packer_info':
					print
					print "Paker info"
					print "-"*60
					for packer in output['pe_info'][item]:
						print packer

				if item == 'mutex_info':
					print
					print "Mutex info"
					print "-"*60
					for mutex in output['pe_info'][item]:
						print mutex

				if item == 'antidbg_info':
					print
					print "Antidbg info"
					print "-"*60
					for antidbg in output['pe_info'][item]:
						print antidbg

				if item == 'antivm_info':
					print
					print "AntiVM info"
					print "-"*60
					for antivm in output['pe_info'][item]:
						print antivm

				if item == 'apialert_info':
					print
					print "Apialert info"
					print "-"*60
					for apialert in output['pe_info'][item]:
						print apialert

				if item == 'resources_info':
					print
					print "Resources info"
					print "-"*60
					for res in output['pe_info'][item]:
						name = str(res['name'])
						size = str(res['size'])
						data = str(res['data'])[0:35]
						data = re.sub(r'\t|\n|\r|\s+', ' ', data)
						print name.ljust(15), size.ljust(8), data

				if item == 'import_function':
					print
					print "Import function"
					print "-"*60
					for func in output['pe_info'][item]:
						f = len(output['pe_info'][item][func])
						print func.ljust(15), str(f)

				if item == 'export_function':
					print
					print "Export function"
					print "-"*60
					for func in output['pe_info'][item]:
						if func['function'] is None:
							print "Unnamed export".ljust(15), func['address']
						else:
							print func['function'][0:15].ljust(15), func['address']

				if item == 'sections_info':
					for secsusp in output['pe_info'][item]:
						if secsusp['suspicious']:
							print
							print "Sections suspicious"
							print "-"*60
							suspicious = True
							break
					if suspicious:
						y = 0
						for secsusp in output['pe_info'][item]:
							for elem in secsusp:
								if secsusp['suspicious']:
									print elem.ljust(15), secsusp[elem]
									y = y+1
							if y > 1 and y < x*7 and secsusp['suspicious']: print

	if output['file_found']:
		print
		print "Filename found"
		print "-"*60
		for item in output['file_found']:
			for fname in output['file_found'][item]:
				print item.ljust(15), fname

	if output['url_found']:
		print
		print "Url found"
		print "-"*60
		for item in output['url_found']:
			print item

	if output['ip_found']:
		print
		print "IP found"
		print "-"*60
		for item in output['ip_found']:
			print item

	if output['fuzzing']:
		print
		print "Fuzzing match"
		print "-"*60
		for item in output['fuzzing']:
			print str(len(output['fuzzing'][item])).ljust(15), item

	if output['pe_info']:
		for item in output['pe_info']:
			if output['pe_info'][item]:
				if item == 'meta_info':
					print
					print "Meta info"
					print "-"*60
					for meta in output['pe_info'][item]:
						print meta.ljust(15), output['pe_info'][item][meta]

#______________________Main______________________

def main():
	# 옵션 개수가 0개거나 3개이상일떄 help 실행
	if len(sys.argv) == 1:
		help.help()
		exit(0)
	# 옵션이 1개이고 -h 나 --help 일때 help 실행
	if len(sys.argv) == 2 and sys.argv[1] == "-h" or sys.argv[1] == "--help":
		help.help()
		exit(0)
	# 옵션이 1개이고 -v나 --verionh 일때 version 출력
	if len(sys.argv) == 2 and sys.argv[1] == "-v" or sys.argv[1] == "--version":
		print help.VERSION
		exit(0)

	# 파일이름의 절대경로를 받어 _ROOT에 저장
	_ROOT = os.path.abspath(os.path.dirname(__file__))

	# 경로 연결후 반환
	def get_data(path):
		return os.path.join(_ROOT, 'signatures', path)

	# Load local file stringsmatch.json
	# signatures 폴더에 있는 stringsmatch.json 파일을 load 하여 경로를 저장한다
	fn_stringsmatch	= get_data('stringsmatch.json')
	global strings_match
	with open(fn_stringsmatch) as data_file:
		strings_match = json.load(data_file)

	# Load PEID userdb.txt database
	global userdb
	userdb = get_data('userdb.txt')

	global filename, fname, fsize, ftype, pe

	# Auto Analysis
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		isfile(filename)
		fname = os.path.basename(filename) #파일 이름
		fsize = os.path.getsize(filename) #파일 사이즈
		ftype = filetype(filename) # 파일 타입
		if re.match(r'^PE[0-9]{2}|^MS-DOS', ftype):
			pe = pefile.PE(filename)
			stdoutput(get_pe_fileinfo(pe, filename)); exit(0)
		else:
			stdoutput(get_fileinfo(filename)); exit(0)

	# Options
	if len(sys.argv) >= 3:
		if sys.argv[1] == "--json" or sys.argv[1] == "--strings" :
			option = sys.argv[1]
			for i in range(2, len(sys.argv)):
				filename = sys.argv[i]
				isfile(filename)
				fname = os.path.basename(filename)
				fsize = os.path.getsize(filename)
				ftype = filetype(filename)
				print('==========%d번째 파일 분석결괴==========' %(i-1))
				if option == "--json":
					if re.match(r'^PE[0-9]{2}|^MS-DOS', ftype):
						pe = pefile.PE(filename)
						print get_pe_fileinfo(pe, filename);
					else:
						print get_fileinfo(filename);
				elif option == "--strings":
					print stringstat.get(filename);
				else:
					help.help()
			exit(0)
		else:
			for i in range(1, len(sys.argv)):
				print('==========%d번째 파일 분석결괴==========' %(i))
				filename = sys.argv[i]
				isfile(filename)
				fname = os.path.basename(filename) #파일 이름
				fsize = os.path.getsize(filename) #파일 사이즈
				ftype = filetype(filename) # 파일 타입
				if re.match(r'^PE[0-9]{2}|^MS-DOS', ftype):
					pe = pefile.PE(filename)
					stdoutput(get_pe_fileinfo(pe, filename));
				else:
					stdoutput(get_fileinfo(filename));
			exit(0)

if __name__ == '__main__':
		main()
