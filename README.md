## S4 League FPS unlock

- overrides shift fly, scythe uppercut, plasma sword jump attack speeds to something more consistent to 60fps behavior
- allows fps and fov adjustment

### Instructions
- load with an asi loader eg. https://github.com/ThirteenAG/Ultimate-ASI-Loader, ie. put `d3d9.dll`, `s4_league_fps_unlock.asi` and `s4_league_fps_unlock.json` next to the game exe
- `max_framerate`, `field_of_view` and `sprint_field_of_view` can be adjusted in `s4_league_fps_unlock.json`, setting `max_framerate` to 0 disables the frame limiter and lets the game go as fast as it can
	- game runs on rough milisecond precision, recommend keeping framerate below 300
- `framelimiter_full_busy_loop` in `s4_league_fps_unlock.json` adjusts the built-in frame limiter's behavior when fps limit is non 0
	- it is set to `false` by default to not fully busy loop before the next frame
	- setting it to `true` might improve latency at lower framerates, at the cost of busy looping power usage

json.hpp is optained from https://github.com/nlohmann v3.11.3 release
