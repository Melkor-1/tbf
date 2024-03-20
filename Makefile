all:
	gcc-13 -O3 tbf.c tbf_util.c -o tbf

debug:
	gcc-13 -DNDEBUG -g3 -ggdb tbf.c tbf_util.c -o tbf

clean:
	rm tbf
