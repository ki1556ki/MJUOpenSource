#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PEframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PEframe. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------
#파일을 읽어서 wlist 에 매 줄을 등록 후 wlist 리턴, 예외 경우에는 False 값 리턴,
def get(filename):
	try:
		fname = open(filename,'r')
		wlist = fname.read().split('\n')
		fname.close
	except:
		return False
		return wlist
#api 파일을 읽고 wlist에 등록 후 리턴, 이 밖에 경우에는 파일을 찾을수 없다는 글 출력
def get_apilist(filename):
	wlist = get(filename)
	if wlist:
		return wlist
	print "File not found ["+filename+"]"
	exit(0)
