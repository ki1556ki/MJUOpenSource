# get함수, pe, strings_match를 파라미터로 가지며 array를 리스트로만들어 정렬한다음 리턴
def get(pe, strings_match):
	# antidbgs에 딕셔너리형식인strigns_match의 키값인 antidbg의 value값을 찾아서 넣어줌 
	antidbgs = strings_match['antidbg']
	array = []
	# pe에 DIRECTORY_ENTRY_IMPORT변수가 있다면 참 없다면 거짓을 판별하여 DEI에 넣어줌
	DEI   = hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
	if DEI:
		# array배열뒤에 imp.name을 넣어주는 반복알고리즘
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in lib.imports:
				for antidbg in antidbgs:
					if antidbg:
						if str(imp.name).startswith(antidbg):
							array.append(imp.name)

	return sorted(set(array))
