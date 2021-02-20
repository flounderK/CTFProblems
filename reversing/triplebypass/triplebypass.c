#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <time.h>
#include <sys/mman.h>
#include <ctype.h>


extern unsigned char* _start;
extern unsigned char* __etext;
//This should be defined in the makefile, but just incase. This should be less than the
//length of the shortest line in the music lyrics
#ifndef SHORTESTLINE
#define SHORTESTLINE 8
#endif

#ifndef LYRICS_STRING //Sung to the tune of bohemian rhapsody
#define LYRICS_STRING { "THIS SHOULD NOT SHOW UP INNN", "YOUR COMP-IL-ED BI-NAR-Y" }
#endif

// You can't LD_PRELOAD over a SIGKILL...
#ifdef MEAN
#define EXIT_METHOD raise(SIGKILL);
#else
#define EXIT_METHOD exit(0);
#endif

#ifndef KEY //This should look like a jumble of data in the binary, not the actual flag value
#define KEY 0x0
#endif

#ifndef LYRICS_LINE_COUNT
#define LYRICS_LINE_COUNT 58
#endif

char* lyrics[LYRICS_LINE_COUNT] = LYRICS_STRING;
int DetectBreakpoints();
void taunt_and_slap();

char *strrev(char *str)
{
    //https://stackoverflow.com/questions/8534274/is-the-strrev-function-not-available-in-linux
    char *p1, *p2;

    if (! str || ! *str)
        return str;
    for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
    {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
    return str;
}

/*
char * xor_ish(char* a, char* b){
    //Main xor_ish

    char* longer = NULL;
    char* shorter = NULL;
    if (strlen(*a) > strlen(*b)){
        longer = &a;
        shorter = &b;
    }
    else{
        longer = &b;
        shorter = &a;
    }

    int mult = ((int)floor(strlen(longer) / strlen(shorter)));
    int pad = strlen(longer) % strlen(shorter);

    return "a";
}
*/

int get_string_length(char* string){
    // does not include line terminator
    size_t i = 0;
    while (string[i] != '\0') {
        i++;
    }
    return i;
}

int check_vowel(char ch){
    if (tolower(ch) == 'a' || tolower(ch) == 'e' || tolower(ch) == 'i' || tolower(ch) == 'o' || ch == 'u' || tolower(ch) == 'y')
        return 1;
    return 0;
}

int count_vowels(char* line){
    int vowel_count = 0;
    for (int i = 0; line[i] != '\0'; ++i){
        vowel_count += check_vowel(line[i]);
    }
    return vowel_count;
}

//void encode_line(char** lines, int line_no){
void encode_line(char** lines){
    for(int i=0; i < LYRICS_LINE_COUNT; i++){
        puts(lines[i]);
        printf("%p\n",lines[i]);
        for(int x = 0; x < strlen(lines[i]); x++){
            char c = lines[i][x];
            *(lines[i] + x) = 'A';
            printf("%d: %p\n",i, &(lines[i][x]));
        }
    }
/*
    //int vowels = count_vowels(line);
    int i = 0;
    //char c;
    for (int i = 0; strlen(line); i++){
        printf("%c\n", (char)line[i]);
        //c = line[i] ^ (char)(vowels % 255);
        //line[i] = c;
        //line[i] ^= ((line_no + 1)%255);
    }
    */
}

int DetectBreakpoints() {
    // Absolutely stolen from https://dev.to/lethalbit/anti-debugging-111-you-are-not-breakable-1nao
    return 0;

    char* start = (char*)&_start;
    char* end = (char*)&__etext;
    int result = 0;
    while (start != end){
        if (((*(volatile unsigned*)start) & 0xff) == 0xcc){
            result = 1;
            printf("Great Job!\n");
            taunt_and_slap();
        }
        ++start;
    }
    return result;
}

void * checkfordebugbytime(){
    //Start this in seperate thread.
    //If it takes too long to return the time super often then we might need to modify the delta_time check
    struct timespec ts;
    long start_time;
    long end_time;
    long delta_time;
    while (1){
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            taunt_and_slap();
        }
        start_time = (&ts)->tv_nsec;
        end_time = (&ts)->tv_nsec;
        delta_time = end_time - start_time;
        //If it takes too long for the timer to return, fuck it
        if (delta_time > 2000) {
            taunt_and_slap();
        }
    }
}

void sing(){
    int i = 0;
    while (i <= LYRICS_LINE_COUNT){
        puts(lyrics[i]);
        i++;
    }
}

void taunt_and_slap(){
   sing();
   EXIT_METHOD
}
/*
void tls_callback(){
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, checkfordebugbytime, NULL);
}
*/

int main() {
#ifndef DEBUG
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1){
        printf("Nice one!\n");
        EXIT_METHOD
    }
#endif
    //char* strings[2] = {"Hello", "world"};
    printf("Thank you for using the shit encryption system. Please enter your account number to decrypt your data\n");
    // read characters of input
    char str[100];
    scanf("%s", str);

    int line_no = 0;
    //printf("%lu", sizeof(lyrics));
    size_t * line_addr;
    char* line;
    //while (line_no < LYRICS_LINE_COUNT)
    //for(line_no=0; line_no < LYRICS_LINE_COUNT; line_no++)
    //for(line_no=0; line_no < 2; line_no++)
    //{
        /*
#ifndef DEBUG
        if (line_no == ((int)ceil(LYRICS_LINE_COUNT / 2)))
            DetectBreakpoints();
#endif
        printf("%s\n", lyrics[line_no]);
        line_addr = (size_t*)malloc(sizeof(lyrics[line_no]));
        memset(&line_addr, 0, sizeof(lyrics[line_no]));
        line = ((char*)line_addr);
        strcpy(line, lyrics[line_no]);
        //encode_line(line, line_no);
        printf("%s\n", lyrics[line_no]);
        line_no++;
        */
        //encode_line(strings[line_no], line_no);
        encode_line(lyrics);
    //}
}
