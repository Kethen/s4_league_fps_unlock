unlocks framerate and makes a static speed modifier dynamic

also overrides shift fly, scythe uppercut, plasma sword jump attack speeds to something more consistent to 60fps behavior

load with an asi loader eg. https://github.com/ThirteenAG/Ultimate-ASI-Loader, ie. put `d3d9.dll`, `s4_league_fps_unlock.asi` and `s4_league_fps_unlock.json` next to the game exe

fov and fps limit can be adjusted in `s4_league_fps_unlock.json`, setting fps limit to 0 lets the game go as fast as it can, fov is only applied in-match

json.hpp is optained from https://github.com/nlohmann v3.11.3 release
