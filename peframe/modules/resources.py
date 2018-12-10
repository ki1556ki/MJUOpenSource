# -*- coding: utf-8 -*-
import pefile
import string

"""검사하려는 파일의 유형 검사. 유형에따른 분류는 아래에 번역."""

res_array = []
def get(pe):
	try:
		for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries: #리소스 종류가 정의되있는 디렉토와 파일 비교.
			if resource_type.name is not None: #리소스 타입이 정의된 경우
				name = "%s" % resource_type.name #리소스의 타입을 정수로 받아 이름을 저장
			else:
				name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id) #리소스 이름을 resource_type.struct.Id 통해 받아옴

			if name == None: #두 경우가 아닌경우
				name = "%d" % resource_type.struct.Id #구조체의 이름을 리소스 이름으로 정의

			if hasattr(resource_type, 'directory'): # resource_type 에 directory 변수가 있는지 확인.
				for resource_id in resource_type.directory.entries: # 모든 디렉토리 검사.
					if hasattr(resource_id, 'directory'): # resource_id 에 directory 변수가 있는지 검사.
						for resource_lang in resource_id.directory.entries: # resource_id.directory.entries
							try:
								data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
								#리소스의 구조가 정의되있고 사이즈가 같다면
							except:
								pass
							lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*') #pefile.LANG.get 함수를 이용해 리소스 이름이 있다면 지정. 없다면 unknown으로 지정
							sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
							#언어 형식지정을 위한 sublang 사용 (pefile에 정의되있음)

							"""모든값은 16진수로 저장됨"""

							data = filter(lambda x: x in string.printable, data) #람다식을 이용해 16진수값을 출력가능한 값으로 변환

			#print 이름, 데이터, hex(resource_lang.data.struct.OffsetToData),리소스 사이즈 출력
			res_array.append({"name": name, "data": data, "offset": hex(resource_lang.data.struct.OffsetToData), "size": resource_lang.data.struct.Size, "language": lang, "sublanguage": sublang})
	except:
		pass

	return res_array

'''
# 자원 유형					# 설명
RT_CURSOR = 1				# 하드웨어 종속 커서 자원.
RT_BITMAP = 2 				# 비트 맵 리소스.
RT_ICON = 3 				# 하드웨어 종속 아이콘 리소스.
RT_MENU = 4 				# 메뉴 자원.
RT_DIALOG = 5				# 대화 상자.
RT_STRING = 6 				# 문자열 테이블 항목.
RT_FONTDIR = 7 				# 글꼴 디렉토리 자원.
RT_FONT = 8 				# 글꼴 리소스.
RT_ACCELERATOR = 9 			# 가속기 테이블.
RT_RCDATA = 10 				# 응용 프로그램 정의 리소스 (원시 데이터).
RT_MESSAGETABLE = 11 		# 메시지 테이블 항목.
RT_VERSION = 16 			# 버전 리소스.
RT_DLGINCLUDE = 17 			# 리소스 편집 도구로 문자열을 .rc 파일과 연관시킬 수 있습니다.
RT_PLUGPLAY = 19 			# 플러그 앤 플레이 리소스.
RT_VXD = 20 				# VXD.
RT_ANICURSOR = 21 			# 움직이는 커서.
RT_ANIICON = 22 			# 애니메이션 아이콘.
RT_HTML = 23 				# HTML 리소스.
RT_MANIFEST = 24 			# Side-by-Side Assembly Manifest.

RT_GROUP_CURSOR = RT_CURSOR + 11 # 하드웨어 독립적 인 커서 리소스.
RT_GROUP_ICON = RT_ICON + 11 # 하드웨어 독립적 인 아이콘 리소스.
'''
