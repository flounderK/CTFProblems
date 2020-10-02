#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>


void store_a_charstar();
void menu();
void store_floats();
void hint();
int float_hoard_max = 400;
float FLOAT_HOARD[400];
int key1 = 0;
int key2 = 0;
int key3 = 0;
int floatcount = 0;

void setup() {
    //FILE* f = fopen("flag.txt", "rt");
    //char c = fgetc(f);
    //c = '\n';
    //fputc(c, stdout);
    //fclose(f);

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

int main(int argc, char **argv) {
    setup();
    char* inp[8];
    int selection;

    for (;;) {
        fflush(stdin);
        menu();
        //scanf("%d", &selection);
        read(0, &inp, 4);
        selection = atoi((char*)&inp);
        switch (selection){
            case 1:
                store_floats();
                break;
            case 2: store_a_charstar();
                break;
            case 3:
                exit(0);
                break;
            case 4:
                hint();
                break;
            default:
                puts("Invalid option. What will become of your magnificent float hoard?");
                exit(1);
        }
    }
}

void hint() {
    puts("Ooo you found the secret hint!");
    puts("Did you know that scanf can consider non numeric characters to be a part of a float?");
}
void win() {
    char flagbuf[64];
    int f;
	int c;
    f = open("flag.txt", O_RDONLY);
    if (key1 != 27000 && key2 != 0xbadf00d && key3 != 0x1337){
        close(f);
        exit(1);
    }
    if (f == 0x0){
        close(f);
        exit(1);
    }
    read(f, &flagbuf, 0x40);
    printf(flagbuf);

    close(f);
}
void set_key1() {
    if (key3 != 0)
        key1 = 27000;
}

void ahhhhhhhh() {
    if (key1 == 0)
        return;
    key3 = 0;
    key2 = key2 + 0xbad0000;
}

void food() {
    key2 = key2 + 0xf00d;
}

void number3() {
    key3 = 0x1337;
}

void menu() {
    puts("Welcome to the Floating Point Dungeon");
    puts("What would you like to do?");
    puts("1. Store precious floats for later.");
    puts("2. Store a disappointing char * .");
    puts("3. Exit, abandoning your hoard of floats");
    printf(" (menu)> ");
}

void store_a_charstar() {
    fflush(stdout);
    char s[8];
    puts("Give me the char * ");
    printf(" (string)> ");
	//fgets(s, 24, stdin);
    read(0, &s, 24);
}

void store_floats() {
    float f;
    f = 0;
    puts("Tell me about your favorite floating point number:");
    printf(" (floats)> ");
    scanf("%f", &f);
    fflush(stdin);
    FLOAT_HOARD[floatcount] = f;
    floatcount++;
}
