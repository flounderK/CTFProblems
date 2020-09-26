#include <stdio.h>
#include <stdlib.h>


void store_a_charstar();
void menu();
void store_floats();
void hint();
float FLOAT_HOARD[400];
int key1 = 0;
int key2 = 0;
int key3 = 0;
int floatcount = 0;

void setup() {
    FILE* f = fopen("flag.txt", "rt");
    char c = fgetc(f);
    printf("%c", c);
    fclose(f);

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
}

int main(int argc, char **argv) {
    setup();
    int selection;
    for (;;) {
        menu();
        fflush(stdin);
        scanf("%d", &selection);
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
                puts("That wasn't quite valid. Try again. ");
                break;
        }
    }
}

void hint() {
    puts("Ooo you found the secret hint!");
    puts("Did you know that scanf can consider non numeric characters to be a part of a float?");
}

void win() {
	FILE *f;
	char c;
    f = fopen("flag.txt", "rt");
    if (key1 != 27000 && key2 != 0xbadf00d && key3 != 0x1337){
        fclose(f);
        exit(1);
    }
    while ( (c = fgetc(f)) != EOF ) {
        printf("%c", c);
        fflush(stdout);
    }
    fclose(f);
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
    char s[8];
    puts("Give me the char * ");
    printf(" (string)> ");
	fgets(s, 24, stdin);
    fflush(stdin);
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
