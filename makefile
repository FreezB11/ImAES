cc = g++
flags = -Wall

files = main.cc ImAES.cc

all:
	${cc} -o ImAES ${files} ${flags}