set -xe
CC=i686-w64-mingw32-gcc
CPP=i686-w64-mingw32-c++
$CPP -g -fPIC -c s4_league_fps_unlock.cpp -std=c++20 -o s4_league_fps_unlock.o
$CC -g -shared -o s4_league_fps_unlock.asi s4_league_fps_unlock.o -Wl,-Bstatic -lpthread -static-libgcc -static-libstdc++
