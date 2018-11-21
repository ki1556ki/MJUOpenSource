import pefile

'''전체 메소드 설명 - 각 메소드마다 pefile형식을 pe파라미터로 받아 각 get_이름 대로로 변수를 만들어 처음에 DIRECTORY_ENTRY_이름[0]의 struct넣는다
예외시 DIRECTORY_ENTRY_IMPORT의 struct를 넣는다 이것 또한 예외시 자DIRECTORY_ENTRY_IMPORT를 넣어주고 각각 리턴 만약 3개다 예외시 거짓 리턴'''


def get_import(pe):
	try:
		imports = pe.DIRECTORY_ENTRY_IMPORT[0].struct
	except:
		try:
			imports = pe.DIRECTORY_ENTRY_IMPORT.struct
		except:
			try:
				imports = pe.DIRECTORY_ENTRY_IMPORT
			except:
				return False
	
	return imports

def get_export(pe):
	try:
		exports = pe.DIRECTORY_ENTRY_EXPORT[0].struct
	except:
		try:
			exports = pe.DIRECTORY_ENTRY_EXPORT.struct
		except:
			try:
				exports = pe.DIRECTORY_ENTRY_EXPORT
			except:
				return False

	return exports

def get_resource(pe):
	try:
		resources = pe.DIRECTORY_ENTRY_RESOURCE[0].struct
	except:
		try:
			resources = pe.DIRECTORY_ENTRY_RESOURCE.struct
		except:
			try:
				resources = pe.DIRECTORY_ENTRY_RESOURCE
			except:
				return False

	return resources

def get_debug(pe):
	try:
		debug = pe.DIRECTORY_ENTRY_DEBUG[0].struct
	except:
		try:
			debug = pe.DIRECTORY_ENTRY_DEBUG.struct
		except:
			try:
				debug = pe.DIRECTORY_ENTRY_DEBUG
			except:
				return False

	return debug

def get_tls(pe):
	try:
		tls = pefile.DIRECTORY_ENTRY_TLS[0].struct
	except:
		try:
			tls = pe.DIRECTORY_ENTRY_TLS.struct
		except:
			try:
				tls = pe.DIRECTORY_ENTRY_TLS
			except:
				return False

	return tls

def get_basereloc(pe):
	try:
		basereloc = pefile.DIRECTORY_ENTRY_BASERELOC[0].struct
	except:
		try:
			basereloc = pe.DIRECTORY_ENTRY_BASERELOC.struct
		except:
			try:
				basereloc = pe.DIRECTORY_ENTRY_BASERELOC
			except:
				return False

	return basereloc
