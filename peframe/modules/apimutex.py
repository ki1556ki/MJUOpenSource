# mutex키값을 antidbgs에 넣어주고 array문자열 배열뒤에 새로운 문자열을 추가하고 리스트, 정렬함
def get(pe, strings_match):
	# antidbgs안에 딕셔너리 형식의strings_match에서 key값인 mutex의 value값을 찾아 넣어줌
	antidbgs = strings_match['mutex']
	array = []
	# pe안에 DIRECTORY_ENTRY_IMPORT변수가 존재하면 참 없다면 거짓
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
