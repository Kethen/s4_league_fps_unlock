#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <pthread.h>

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

void patch_min_frametime(double min_frametime){
	LOG("patching minimal frametime to %f", min_frametime);
	double *min_frametime_const = (double *)0x013d33a0;
	*min_frametime_const = min_frametime;
}

void *main_thread(void *arg){
	return NULL;
}

__attribute__((constructor))
int init(){
	log_file = fopen("s4_league_fps_unlock.log", "w");
	LOG("mhmm library loaded");

	patch_min_frametime(8.0);

	LOG("now starting main thread");
	pthread_t thread;
	pthread_create(&thread, NULL, main_thread, NULL);

	LOG("gcc constructor ending");
	return 0;
}
