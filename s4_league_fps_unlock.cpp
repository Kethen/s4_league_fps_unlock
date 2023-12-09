#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <pthread.h>
#include <cstring>

// mingw don't provide a mprotect wrap
#include <memoryapi.h>

FILE *log_file = NULL;
#define LOG(...) \
{ \
	char buf[500]; \
	snprintf(buf, sizeof(buf), __VA_ARGS__); \
	int len = strlen(buf); \
	if(len + 1 < sizeof(buf)){ \
		buf[len] = '\n'; \
		buf[len + 1] = '\0'; \
	} \
	if(log_file != NULL){ \
		fprintf(log_file, "%s", buf); \
		fflush(log_file); \
	}else{ \
		printf("warning: log_file is NULL, logging to stdout \n"); \
		printf("%s", buf); \
	} \
}

#define VERBOSE 0
#if VERBOSE
	#define LOG_VERBOSE(...) LOG(__VA_ARGS__)
#else // VERBOSE
	#define LOG_VERBOSE(...)
#endif //VERBISE

// function at 00871970, not essentially game tick
static void (*orig_game_tick)(void);
static void patched_game_tick(void){
	register int ecx asm("ecx");
	int ecx_copy = ecx;
	LOG_VERBOSE("game tick function hook fired");
	ecx = ecx_copy;
	orig_game_tick();
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
	LOG("mhmm library loaded");

	patch_min_frametime(8.0);
	hook_game_tick();

	LOG("now starting main thread");
	pthread_t thread;
	pthread_create(&thread, NULL, main_thread, NULL);

	LOG("gcc constructor ending");
	return 0;
}
