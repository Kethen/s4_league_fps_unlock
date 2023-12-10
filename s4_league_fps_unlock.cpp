#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <pthread.h>
#include <cstring>
#include <cmath>

// mingw don't provide a mprotect wrap
#include <memoryapi.h>

#define ENABLE_LOGGING 1

#if ENABLE_LOGGING
FILE *log_file = NULL;
char log_buf[500];
pthread_mutex_t log_mutex;

#define LOG(...) \
{ \
	pthread_mutex_lock(&log_mutex); \
	snprintf(log_buf, sizeof(log_buf), __VA_ARGS__); \
	int _len = strlen(log_buf); \
	if(_len + 1 < sizeof(log_buf)){ \
		log_buf[_len] = '\n'; \
		log_buf[_len + 1] = '\0'; \
	} \
	if(log_file != NULL){ \
		fprintf(log_file, "%s", log_buf); \
		fflush(log_file); \
	}else{ \
		printf("warning: log_file is NULL, logging to stdout \n"); \
		printf("%s", log_buf); \
	} \
	pthread_mutex_unlock(&log_mutex); \
}

#else // ENABLE_LOGGING
#define LOG(...)
#endif //ENABLE_LOGGING

#define VERBOSE 0
#if VERBOSE
	#define LOG_VERBOSE(...) LOG(__VA_ARGS__)
#else // VERBOSE
	#define LOG_VERBOSE(...)
#endif //VERBOSE

// __sync_synchronize() is not enough..?
#define INIT_MEM_FENCE() \
static bool _mem_fence_ready = 0; \
static pthread_mutex_t _mem_fence; \
if(!_mem_fence_ready){ \
	if(pthread_mutex_init(&_mem_fence, NULL)){ \
		LOG("failed to initialize mem fence for %s", __FUNCTION__); \
		exit(1); \
	} \
	_mem_fence_ready = true; \
}

#define MEM_FENCE() \
pthread_mutex_lock(&_mem_fence); \
pthread_mutex_unlock(&_mem_fence);

struct __attribute__ ((packed)) time_context{
	double unknown;
	double last_t;
	double delta_t;
	float delta_t_modifier;
};

struct __attribute__ ((packed)) game_context{
	// 0x48 debug toggle? 1 byte
	// 0x49 fps limiter toggle 1 byte
	// 0x4c unknown 1 byte
	// 0x4a unknown 1 byte
	uint8_t unknown[0x48];
	uint8_t online_verbose_toggle;
	uint8_t fps_limiter_toggle;
};

static struct game_context *(*fetch_game_context)(void) = (struct game_context *(*)(void)) 0x004ad790;
static void (__attribute__((thiscall)) *update_time_delta)(struct time_context *ctx) = (void (__attribute__((thiscall)) *)(struct time_context *ctx)) 0x00ff7f30;

struct __attribute__ ((packed)) fun_007b0180_ctx{
	// float 0x684 x, 0x688 y, 0x68c z
	uint8_t unknown[0x684];
	float x;
	float y;
	float z;
};

static void (__attribute__((thiscall)) *orig_fun_007b0180)(void*, float, float, float, uint32_t);
static void __attribute__((thiscall)) patched_fun_007b0180(struct fun_007b0180_ctx *ctx, float param_1, float param_2, float param_3, uint32_t param_4){
	INIT_MEM_FENCE()
	float before_x = ctx->x;
	float before_y = ctx->y;
	float before_z = ctx->z;

	MEM_FENCE();

	orig_fun_007b0180(ctx, param_1, param_2, param_3, param_4);

	MEM_FENCE();

	float after_x = ctx->x;
	float after_y = ctx->y;
	float after_z = ctx->z;

	float delta_x = after_x - before_x;
	float delta_y = after_y - before_y;
	float delta_z = after_z - before_z;

	bool log = false;
	if(abs(delta_x) < 1 && abs(delta_z) < 1 && abs(delta_y) >=1){
		log = true;
	}else if((abs(delta_x) >= 1 || abs(delta_z) >= 1) && abs(delta_y) < 1){
		log = true;
	}

	void * ret_addr = __builtin_return_address(0);

	if(log){
		LOG("%s: ctx 0x%08x, param_1 %f, param_2 %f, param_3 %f, param_4 %u", __FUNCTION__, ctx, param_1, param_2, param_3, param_4);
		LOG("%s: %f->%f %f->%f %f->%f", __FUNCTION__, before_x, after_x, before_y, after_y, before_z, after_z);
		LOG("%s: %f %f %f", __FUNCTION__, after_x - before_x, after_y - before_y, after_z - before_z);
		LOG("%s: return addr: 0x%08x", __FUNCTION__, ret_addr);
	}
}

static void hook_fun_007b0180(){
	LOG("let's see what 0x007b0180 does");

	uint8_t intended_trampoline[] = {
		// space for original instruction
		0, 0, 0, 0, 0, 0, 0, 0, 0,
		// MOV eax,0x007b0189
		0xb8, 0x89, 0x01, 0x7b, 0x00,
		// JMP eax
		0xff, 0xe0
	};
	memcpy((void *)intended_trampoline, (void *)0x007b0180, 9);

	uint8_t intended_patch[] = {
		// MOV eax, patched_fun_007b0180
		0xb8, 0, 0, 0, 0,
		// JMP eax
		0xff, 0xe0
	};
	*(uint32_t *)&intended_patch[1] = (uint32_t)patched_fun_007b0180;

	orig_fun_007b0180 = (void (__attribute__((thiscall)) *)(void*, float, float, float, uint32_t))VirtualAlloc(NULL, sizeof(intended_trampoline), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy((void *)orig_fun_007b0180, intended_trampoline, sizeof(intended_trampoline));
	DWORD old_protect;
	VirtualProtect((void *)orig_fun_007b0180, sizeof(intended_trampoline), PAGE_EXECUTE_READ, &old_protect);

	memcpy((void *)0x007b0180, intended_patch, sizeof(intended_patch));
}

// function at 00871970, not essentially game tick
static void (__attribute__((thiscall)) *orig_game_tick)(void *);
static void __attribute__((thiscall)) patched_game_tick(void *tick_ctx){
	LOG_VERBOSE("game tick function hook fired");

	const static float orig_speed_dampener = 0.015;
	const static double orig_fixed_frametime = 1.66666666666666678509045596002E1;
	static float *speed_dampener = (float *)0x015f4210;

	static struct time_context tctx;

	struct game_context *ctx = fetch_game_context();
	LOG_VERBOSE("game context at 0x%08x", (uint32_t)ctx);
	ctx->fps_limiter_toggle = 0;
	orig_game_tick(tick_ctx);

	update_time_delta(&tctx);
	*speed_dampener = tctx.delta_t * orig_speed_dampener / orig_fixed_frametime;
	LOG_VERBOSE("delta_t: %f, speed_dampener: %f", tctx.delta_t, *speed_dampener);
}
static void hook_game_tick(){
	LOG("hooking game tick");
	uint8_t intended_trampoline[] = {
		// original 9 bytes
		0, 0, 0, 0, 0, 0, 0, 0, 0,
		// MOV EAX,0x00871979
		0xb8, 0x79, 0x19, 0x87, 0x00,
		// JMP EAX
		0xff, 0xe0
	};
	memcpy(intended_trampoline, (void *)0x00871970, 9);
	DWORD old_protect;
	orig_game_tick = (void (__attribute__((thiscall)) *)(void *)) VirtualAlloc(NULL, sizeof(intended_trampoline), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(orig_game_tick == NULL){
		LOG("Failed allocating executable memory while preparing trampoline");
		return;
	}
	memcpy((void *)orig_game_tick, intended_trampoline, sizeof(intended_trampoline));
	VirtualProtect((void *)orig_game_tick, sizeof(intended_trampoline), PAGE_EXECUTE_READ, &old_protect);

	uint32_t patched_function_location = (uint32_t)patched_game_tick;
	uint8_t *patch_location = (uint8_t*)0x00871970;
	uint8_t intended_patch[] = {
		// MOV EAX,patched_game_tick
		0xb8, 0, 0, 0, 0,
		// JMP EAX
		0xff, 0xe0,
		// nop nop
		0x90, 0x90
	};
	memcpy((void *)&intended_patch[1], (void *)&patched_function_location, 4);
	memcpy((void *)0x00871970, intended_patch, sizeof(intended_patch));
}

static void patch_min_frametime(double min_frametime){
	LOG("patching minimal frametime to %f", min_frametime);
	double *min_frametime_const = (double *)0x013d33a0;
	*min_frametime_const = min_frametime;
}

static void experinmental_static_patches(){
	LOG("applying experimental patches");
	float *what_is_this = (float *)0x014786d8;
	*what_is_this = 0.0001;
}

static void *main_thread(void *arg){
	return NULL;
}

__attribute__((constructor))
int init(){
	#if ENABLE_LOGGING
	log_file = fopen("s4_league_fps_unlock.log", "w");
	if(pthread_mutex_init(&log_mutex, NULL)){
		printf("logger mutex init failed\n");
		return 0;
	}
	#endif // ENABLE_LOGGING

	LOG("mhmm library loaded");

	hook_game_tick();
	hook_fun_007b0180();

	experinmental_static_patches();

	LOG("now starting main thread");
	pthread_t thread;
	pthread_create(&thread, NULL, main_thread, NULL);

	LOG("gcc constructor ending");
	return 0;
}
