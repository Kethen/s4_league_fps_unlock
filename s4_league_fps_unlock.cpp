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
#endif //VERBISE


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
static void (*update_time_delta_raw)(void) = (void (*)(void)) 0x00ff7f30;
static void update_time_delta(struct time_context *ctx){
	register struct time_context *ecx asm("ecx");
	ecx = ctx;
	update_time_delta_raw();
}

static void (*delay_and_update_time_delta_raw)(double) = (void (*)(double)) 0x00ff7fd0;
static void delay_and_update_time_delta(struct time_context *ctx, double delay_ms){
	register struct time_context *ecx asm("ecx");
	ecx = ctx;
	delay_and_update_time_delta_raw(delay_ms);
}

static void *(*fetch_016ed578)(void) = (void* (*)(void)) 0x01172b00;

void game_tick_replica(void *ctx){
	LOG_VERBOSE("ctx is at 0x%08x", ctx);

	struct time_context *tctx = (struct time_context *)((uint32_t)ctx + 0x8);
	struct game_context *gctx = fetch_game_context();
	if(gctx->fps_limiter_toggle){
		delay_and_update_time_delta(tctx, *(double *)0x013d33a0);
	}else{
		update_time_delta(tctx);
	}
	int time_delta = round(tctx->delta_t);

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("1");
		void (*fun_00872730)(int) = (void (*)(int))0x00872730;
		ecx = (void *)((uint32_t)ctx + 0x28);
		fun_00872730(time_delta);
	}

	uint32_t *dat_01642edc = (uint32_t *)0x01642edc;
	if(*dat_01642edc != 0){
		register void *ecx asm("ecx");
		LOG_VERBOSE("2");
		void (*fun_009ea0a0)(int) = (void (*)(int))0x009ea0a0;
		ecx = (void *)*dat_01642edc;
		fun_009ea0a0(time_delta);
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("3");
		void (*fun_009e9020)(int) = (void (*)(int))0x009e9020;
		uint32_t *dat_01642ed8 = (uint32_t *)0x01642ed8;
		ecx = (void *)*dat_01642ed8;
		fun_009e9020(time_delta);
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("4");
		void (*fun)(void) = (void (*)(void)) *(uint32_t **)(*(uint32_t *)ctx + 0x38);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		ecx = (void *)ctx;
		fun();
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("5");
		void (*fun_00de8cd0)(int) = (void (*)(int))0x00de8cd0;
		uint32_t *dat_01664a80 = (uint32_t *)0x01664a80;
		ecx = (void *)*dat_01664a80;
		fun_00de8cd0(time_delta);
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("6");
		void *unknown_context = fetch_016ed578();
		void (*fun)(void) = (void (*)(void)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x4c);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		ecx = unknown_context;
		fun();
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("7");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t*)0x01642dfc + 0x10c);
		void (*fun)(void) = (void (*)(void)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x34);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		ecx = unknown_context;
		fun();
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("8");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t*)0x01642dfc + 0x10c);
		void (*fun)(void) = (void (*)(void)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x44);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		ecx = unknown_context;
		fun();
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("9");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t*)0x01642dfc + 0x198);
		void (*fun)(int) = (void (*)(int)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x24);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		ecx = unknown_context;
		fun(time_delta);
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("10");
		void *unknown_context = (void *) (*(uint32_t *)0x01643190 + 0x4);
		void (*fun)(int) = (void (*)(int)) *(uint32_t **)(*(uint32_t*)unknown_context + 0x24);
		LOG_VERBOSE("fun is at 0x%08x", (void *)fun);
		ecx = unknown_context;
		fun(time_delta);
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("11");
		double unknown_double = (time_delta % 4000) + *(double *)0x013a89b0;
		uint32_t unknown_local_context[2];
		void (*fun_0100a940)(float, uint32_t) = (void (*)(float, uint32_t)) 0x0100a940;
		ecx = unknown_local_context;
		fun_0100a940(unknown_double / *(float *)0x013ab2a0, *(uint32_t*)0x014c904c);
		*(uint32_t*)0x016eff30 = *unknown_local_context;
		*(uint32_t*)0x016eff34 = unknown_local_context[1];
	}

	{
		register void *ecx asm("ecx");
		LOG_VERBOSE("10");
		void *unknown_context = (void *)*(uint32_t *)(*(uint32_t *)0x01642dfc + 0x1bc);
		void (*fun_006ea880)(int) = (void (*)(int)) 0x006ea880;
		ecx = unknown_context;
		fun_006ea880(time_delta);
	}

}


// function at 00871970, not essentially game tick
static void (*orig_game_tick)(void);
static void patched_game_tick(void){
	register uint32_t ecx asm("ecx");
	uint32_t ecx_copy = ecx;
	LOG_VERBOSE("game tick function hook fired");
	struct game_context *ctx = fetch_game_context();
	LOG_VERBOSE("game context at 0x%08x", (uint32_t)ctx);
	ctx->online_verbose_toggle = 1;
	ctx->fps_limiter_toggle = 0;
	//ecx = ecx_copy;
	//orig_game_tick();
	game_tick_replica((void *)ecx_copy);
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
	orig_game_tick = (void (*)(void)) VirtualAlloc(NULL, sizeof(intended_trampoline), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
