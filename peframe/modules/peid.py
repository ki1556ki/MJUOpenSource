# -*- coding: utf-8 -*-
import peutils
"""
matches = signatures.match_all(pe, ep_only = True) 함수 설명:

ep_only가 True이면 결과는 패커 이름의 문자열이 됩니다.

그렇지 않으면 양식 목록(file_ofsset, packer_name)이 됩니다.

파일에서 서명이 발견된 위치를 지정합니다.


(사용자 유저 데이터베이스가 신뢰할 수 있는 서명이 되있는지 확인.)
"""
def get(pe, userdb):
	signatures = peutils.SignatureDatabase(userdb) #구문 분석 된 PEiD 서명 데이터베이스를 로드하고 유지. (신뢰할 수 있는 유저 데이터베이스 로드.)
	matches = signatures.match_all(pe, ep_only = True) #일치하는 모든 항목을 검색하여 반환합니다.


	array = []
	if matches:
		for item in matches:
			# remove duplicate
			if item[0] not in array:
				array.append(item[0])
#서명 확인되면 배열에 추가하고 반환,
	return array
