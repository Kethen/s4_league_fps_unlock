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

static void (__attribute__((thiscall))  *delay_and_update_time_delta)(struct time_context *, double) = (void (__attribute__((thiscall)) *)(struct time_context *, double)) 0x00ff7fd0;


static void *(*fetch_016ed578)(void) = (void* (*)(void)) 0x01172b00;

void __attribute__((thiscall)) game_tick_replica(void *ctx){
	LOG_VERBOSE("ctx is at 0x%08x", ctx);

	INIT_MEM_FENCE();

	struct time_context *tctx = (struct time_context *)((uint32_t)ctx + 0x8);
	struct game_context *gctx = fetch_game_context();
	if(gctx->fps_limiter_toggle){
		delay_and_update_time_delta(tctx, *(double *)0x013d33a0);
	}else{
		update_time_delta(tctx);
	}
	int time_delta = round(tctx->delta_t);

	{
		LOG_VERBOSE("1");
		void (__attribute__((thiscall)) *fun_00872730)(void *, int) = (void (__attribute__((thiscall)) *)(void *, int))0x00872730;
		void *unknown_context = (void *)((uint32_t)ctx + 0x28);
		MEM_FENCE();
		fun_00872730(unknown_context, time_delta);
	}

	uint32_t *dat_01642edc = (uint32_t *)0x01642edc;
	if(*dat_01642edc != 0){
		LOG_VERBOSE("2");
		void (__attribute__((thiscall)) *fun_009ea0a0)(void *, int) = (void (__attribute__((thiscall))*)(void *, int))0x009ea0a0;
		void *unknown_context = (void *)*dat_01642edc;
		MEM_FENCE();
		fun_009ea0a0(unknown_context, time_delta);
	}

	{
		LOG_VERBOSE("3");
		void (__attribute__((thiscall)) *fun_009e9020)(void *, int) = (void (__attribute__((thiscall)) *)(void *, int))0x009e9020;
		uint32_t *dat_01642ed8 = (uint32_t *)0x01642ed8;
		void *unknown_context = (void *)*dat_01642ed8;
		MEM_FENCE();
		fun_009e9020(unknown_context, time_delta);
	}

	{
		LOG_VERBOSE("4");
		void (__attribute__((thiscall)) *fun)(void *) = (void (__attribute__((thiscall)) *)(void *)) *(uint32_t **)(*(uint32_t *)ctx + 0x38);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		MEM_FENCE();
		fun((void *)ctx);
	}

	{
		LOG_VERBOSE("5");
		void (__attribute__((thiscall)) *fun_00de8cd0)(void *, int) = (void (__attribute__((thiscall)) *)(void*, int))0x00de8cd0;
		uint32_t *dat_01664a80 = (uint32_t *)0x01664a80;
		void *unknown_context = (void *)*dat_01664a80;
		MEM_FENCE();
		fun_00de8cd0(unknown_context, time_delta);
	}

	{
		LOG_VERBOSE("6");
		void *unknown_context = fetch_016ed578();
		void (__attribute__((thiscall)) *fun)(void *) = (void (__attribute__((thiscall)) *)(void *)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x4c);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		MEM_FENCE();
		fun(unknown_context);
	}

	{
		LOG_VERBOSE("7");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t*)0x01642dfc + 0x10c);
		void (__attribute__((thiscall)) *fun)(void *) = (void (__attribute__((thiscall)) *)(void *)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x34);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		MEM_FENCE();
		fun(unknown_context);
	}

	{
		LOG_VERBOSE("8");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t*)0x01642dfc + 0x10c);
		void (__attribute__((thiscall)) *fun)(void *) = (void (__attribute__((thiscall)) *)(void *)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x44);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		MEM_FENCE();
		fun(unknown_context);
	}

	{
		LOG_VERBOSE("9");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t*)0x01642dfc + 0x198);
		void (__attribute__((thiscall)) *fun)(void *, int) = (void (__attribute__((thiscall)) *)(void *, int)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x24);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		MEM_FENCE();
		fun(unknown_context, time_delta);
	}

	{
		LOG_VERBOSE("10");
		void *unknown_context = (void *) (*(uint32_t *)0x01643190 + 0x4);
		void (__attribute__((thiscall)) *fun)(void*, int) = (void (__attribute__((thiscall)) *)(void *, int)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x24);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		MEM_FENCE();
		fun(unknown_context, time_delta);
	}

	{
		LOG_VERBOSE("11");
		double unknown_double = (time_delta % 4000) + *(double *)0x013a89b0;
		uint32_t unknown_local_context[2];
		void (__attribute__((thiscall)) *fun_0100a940)(uint32_t *, float, uint32_t) = (void (__attribute__((thiscall)) *)(uint32_t *, float, uint32_t)) 0x0100a940;
		MEM_FENCE();
		fun_0100a940(unknown_local_context, unknown_double / *(float *)0x013ab2a0, *(uint32_t*)0x014c904c);
		*(uint32_t*)0x016eff30 = *unknown_local_context;
		*(uint32_t*)0x016eff34 = unknown_local_context[1];
	}

	{
		LOG_VERBOSE("12");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t *)0x01642dfc + 0x1bc);
		void (__attribute__((thiscall)) *fun_006ea880)(void *, int) = (void (__attribute__((thiscall)) *)(void *, int)) 0x006ea880;
		MEM_FENCE();
		fun_006ea880(unknown_context, time_delta);
	}
}


// function at 00871970, not essentially game tick
static void (__attribute__((thiscall)) *orig_game_tick)(void *);
static void __attribute__((thiscall)) patched_game_tick(void *tick_ctx){
	LOG_VERBOSE("game tick function hook fired");
	INIT_MEM_FENCE();

	struct game_context *ctx = fetch_game_context();
	LOG_VERBOSE("game context at 0x%08x", (uint32_t)ctx);
	ctx->online_verbose_toggle = 1;
	ctx->fps_limiter_toggle = 0;
	MEM_FENCE();
	//orig_game_tick(tick_ctx);
	game_tick_replica(tick_ctx);
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

static void *main_thread(void *arg){
	return NULL;
}

__attribute__((constructor))
int init(){
	log_file = fopen("s4_league_fps_unlock.log", "w");
	if(pthread_mutex_init(&log_mutex, NULL)){
		printf("logger mutex init failed\n");
		return 0;
	}
	LOG("mhmm library loaded");

	patch_min_frametime(8.0);
	hook_game_tick();

	LOG("now starting main thread");
	pthread_t thread;
	pthread_create(&thread, NULL, main_thread, NULL);

	LOG("gcc constructor ending");
	return 0;
}
