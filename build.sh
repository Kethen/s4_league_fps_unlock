set -xe
CC=i686-w64-mingw32-gcc
$CC -g -fPIC -c s4_league_fps_unlock.c -o s4_league_fps_unlock.o
$CC -g -shared -o s4_league_fps_unlock.asi s4_league_fps_unlock.o -Wl,-Bstatic -lpthread -static-libgcc
