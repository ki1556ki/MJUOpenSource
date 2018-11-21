
try:
	import pefile
	import peutils
except ImportError: # PE Header 보기위한 pefile,  peid의 DB파일사용을 위한 peutils import. 오류시 에러출력,
	print 'Error: import pefile or peutils modules failed.'
	exit(0)

def get(pe):
	array = []
	for section in pe.sections: # pefile 기능 사용 각 섹션의 정보 확인.
		if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
			#엔트로피 정보가 0이거나 7 이상의 값이 나올경우 바이러스 검사

			"""
			엔트로피가 높은 데이터일수록 나타날 수 있는 모든 비트들이 고루 존재함을 의미하므로 어떤 압축 파일의
			엔트로피 수치가 높을수록 압축률이 높다고 말할 수 있다
			=> 압축율이 높은 파일 검사항목에 추가
			"""

			sc   = section.Name #섹션 이름, md5, sha1정보 변수 저장수 array 형식으로 입력
			md5  = section.get_hash_md5()
			sha1 = section.get_hash_sha1()
			array.append({"Section": sc, "Hash MD5": md5, "Hash SHA-1": sha1})

	return array
