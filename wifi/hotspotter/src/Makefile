LDLIBS		= -lpcap
CFLAGS		= -g3 -ggdb -pipe -Wall
PROGOBJ		= hotspotter.o utils.o 
PROG		= hotspotter

all: $(PROG) $(PROGOBJ)

utils: utils.c utils.h
	$(CC) $(CFLAGS) utils.c -c 

hotspotter: hotspotter.c utils.c utils.h version.h ieee802_11.h hotspotter.h \
    		utils.o
	$(CC) $(CFLAGS) hotspotter.c -o hotspotter utils.o $(LDLIBS)

clean:
	$(RM) $(PROGOBJ) $(PROG) *~
