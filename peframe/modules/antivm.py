# 정규표현식을 이용한 문자열 매칭에 사용되는 파이썬 라이브러리
import re    

# filename을 파라미터로 가져와서 파일처리 후 trk배열 리턴해주는 get함
def get(filename):
	
	trk     = []

	# VM_STR의 정보를 key:value(딕셔너리) 형식으로 나타냄
	VM_Str  = {
		"Virtual Box":"VBox",
		"VMware":"WMvare"
	}
	
	# VM_Sign의 정보를 key:value(딕셔너리) 형식으로 나타냄
	VM_Sign = {
		"Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
		"VirtualPc trick":"\x0f\x3f\x07\x0b",
		"VMware trick":"VMXh",
		"VMCheck.dll":"\x45\xC7\x00\x01",
		"VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
		"Xen":"XenVMM",
		"Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
		"Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
		"Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
		}
		
		"""이전 파라미터에서 가져온 filename을 읽어 match를 findall함수를 이용해 IGNORECASE(대소문자 구분없이), MULTILINE(메타문자^(문자열의처음), $(문자열 마지막) 문자열의 각라인마다 적용
		시켜 match에 값이 없으면 맨뒤에 string을 넣음 """
	with open(filename, "rb") as f:
		buf = f.read()
		for string in VM_Str:
			match = re.findall(VM_Str[string], buf, re.IGNORECASE | re.MULTILINE)
			if match:
				trk.append(string)
		# VM_Sign의 json형식의 개수만큼 반복하면서 만약 buf(파일)안에 VM_Sign[현재index][뒤에서 첫번째 index]값이 -1보다 클경우 trk안의 뒤에 trick을 넣음		
		for trick in VM_Sign:
			if buf.find(VM_Sign[trick][::-1]) > -1:
				trk.append(trick)

	return trk
