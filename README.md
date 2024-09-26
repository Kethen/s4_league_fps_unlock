## S4 League FPS unlock

- overrides shift fly, scythe uppercut, plasma sword jump attack speeds to something more consistent to 60fps behavior
- allows fps and fov adjustment

### Instructions
- load with an asi loader eg. https://github.com/ThirteenAG/Ultimate-ASI-Loader, ie. put `d3d9.dll`, `s4_league_fps_unlock.asi` and `s4_league_fps_unlock.json` next to the game exe
- `max_framerate`, `field_of_view`, `center_field_of_view` and `sprint_field_of_view` can be adjusted in `s4_league_fps_unlock.json`, setting `max_framerate` to 0 disables the frame limiter and lets the game go as fast as it can
	- game runs on rough milisecond precision, recommend keeping framerate below 300
- `framelimiter_full_busy_loop` in `s4_league_fps_unlock.json` adjusts the built-in frame limiter's behavior when fps limit is non 0
	- it is set to `false` by default to not fully busy loop before the next frame
	- setting it to `true` might improve latency when the game is rendering faster than the frame limiter, at the cost of busy looping cpu power usage
- `framelimiter_busy_loop_buffer_100ns` is a mixed approach of `framelimiter_full_busy_loop`, enforcing some busy loop right before the next frame
	- `framelimiter_full_busy_loop` has to be set to false for this to take effect
	- it is set to `15000` by default to not always busy loop but still try and secure cpu resources timely for the next frame
	- when the game is rendering faster than the frame limiter, setting it to `0` would reduce cpu power usage, but might introduce latency and frametime jitter when there are active background tasks

json.hpp is optained from https://github.com/nlohmann v3.11.3 release

### Special thanks
- verreater on discord for in-depth testing and various insights

