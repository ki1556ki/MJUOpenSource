import pefile

# pe.(구조체(매소드)).맴버변수로 이루어짐. 아마도 각각의 변수명 import, export등 대로 DIRECTORY_EXTRY의 key값의 가상 주소를 가져와 이게 거짓이면(주소에값이없으면) dirlist뒤에 추가하여 리턴해줌
def get(pe):
	# The directory of imported symbols
	dir_import = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
	# The directory of exported symbols; mostly used for DLLs.
	dir_export = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
	# Debug directory - contents is compiler dependent.
	dir_debug = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress
	# Thread local storage directory - structure unknown; contains variables that are declared
	dir_tls = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']].VirtualAddress
	# The resources, such as dialog boxes, menus, icons and so on, are stored in the data directory
	dir_resource = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress
	# PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
	dir_relocation = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].VirtualAddress
	# PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
	dir_security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
	
	dirlist   = []
	
	if dir_import:
		dirlist.append("import")
	if dir_export:
		dirlist.append("export")
	if dir_resource:
		dirlist.append("resource")
	if dir_debug:
		dirlist.append("debug")
	if dir_tls:
		dirlist.append("tls")
	if dir_relocation:
		dirlist.append("relocation")
	if dir_security:
		dirlist.append("security")
			
	return dirlist
		return {}
