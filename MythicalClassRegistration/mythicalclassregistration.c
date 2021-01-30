
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include "magicstrings.h"

int MAX_WORD_SIZE = 16; // no section of a class name can contain more characters than this (not including null byte)

int class_name_is_valid(char** classname){
    char *word;
    size_t classname_size = strlen(classname);
    char* delim = "_";
    while ( ( word = (char*)strsep(classname, delim) ) != NULL)
    {
        int word_found = 0;
        int i = 0;
        while (MAGIC_STRINGS[i])
        {
            if (strcmp(MAGIC_STRINGS[i], word) == 0)
            {
                word_found = 1;
                break;
            }
            i++;
        }
        if (word_found == 0)
        {
            return 0;
        }
    }
    return 1;
}


int main(int argc, char ** argv)
{
    void * a;
    scanf("%ms", &a);
    printf("%s\n", a);
    return 0;
}
