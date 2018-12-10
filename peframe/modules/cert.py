# -*- coding: utf-8 -*-
import json
import pefile
import hashlib

def get(pe):

	# Virtual Address
	cert_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

	# Size
	cert_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

	# cert_address가 0이아니고 cert_size가 0이아닐때 해시값을 구해 딕셔너리 형식으로 리턴
	if cert_address != 0 and cert_size !=0:
		signature = pe.write()[cert_address+8:]
		# hashlib함수를 이용해 md5 해시값구하기
		cert_md5  = hashlib.md5(signature).hexdigest()
		# 위와 똑같이 sha 해시값 구함
		cert_sha1 = hashlib.sha1(signature).hexdigest()
		signed = True
		return {"virtual_address": cert_address, "block_size": cert_size, "hash_md5": cert_md5, "hash_sha1": cert_sha1}
	# cert_add가 거짓이고 사이즈가0일때 빈값 반환
	else:
		return {}
