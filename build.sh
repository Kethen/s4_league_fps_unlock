set -xe
CPPC=i686-w64-mingw32-c++
$CPPC -g -fPIC -c s4_league_fps_unlock.cpp -std=c++20 -o s4_league_fps_unlock.o -O0
$CPPC -g -shared -o s4_league_fps_unlock.asi s4_league_fps_unlock.o -Wl,-Bstatic -lpthread -static-libgcc -static-libstdc++
