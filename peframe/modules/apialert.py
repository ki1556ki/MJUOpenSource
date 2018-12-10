# -*- coding: utf-8 -*-
# json 형식 사용을 위한 임폴트
import json

# get함수, 각각의 반복문을 통해 apialert_found안에 문자열 삽입후 리스트형식으로 정렬하여 리턴값 반환.
def get(pe, strings_match):
	alerts = strings_match['apialert']
	apialert_found = []
	# pe에 DIRECTORY_ENTRY_IMPORT라는 변수가 있는지 확인하여 있으면 참 없으면 거짓.
	if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in lib.imports:
				for alert in alerts:
					if alert: # remove 'null'
						# imp.name의 문자열안에 alert의 문자열이 있을경우 apialert_found안의 맨뒤에 imp.name을 넣음
						if str(imp.name).startswith(alert):
							apialert_found.append(imp.name)

	return sorted(set(apialert_found))
