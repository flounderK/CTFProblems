/*
 There are supposed to be a lot of different vulnerabilities in this
 challenge, please don't try to patch them.
 The point of the challenge is to encourage creative solutions and exploration
 of binary exploitation concepts, not to force people to solve it in a specific way.

*/


#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int8_t SHOPPING_CART_INDEX = 0;
#define MAX_SHOPPING_CART_ENTRIES 16

void * SHOPPING_CART[MAX_SHOPPING_CART_ENTRIES] = {NULL};

void print_menu()
{
    puts("1. Register for class");
    puts("2. Edit class shopping cart");
    puts("3. Remove class from shopping cart");
    puts("4. Checkout");
#ifdef DEBUG
    printf("SHOPPING_CART_INDEX: %d\n", SHOPPING_CART_INDEX);
#endif
    printf(" > ");
}

void print_shopping_cart(){
    int i = 0;
    while ( i < MAX_SHOPPING_CART_ENTRIES)
    {
        if (SHOPPING_CART[i] == NULL)
        {
            printf("%d: NULL\n", i);
            i++;
            continue;
        }
        printf("%d: %s\n", i, (char*)SHOPPING_CART[i]);
        i++;
    }
}

void register_for_class()
{
    void * a = NULL;
    if (SHOPPING_CART_INDEX > MAX_SHOPPING_CART_ENTRIES)
    {
        puts("No more room in the shopping cart. Remove a class to continue");
        return;
    }
    puts("Enter the name of the class you want to register for");
    printf(" > ");
    scanf("%ms", &a);
    // validate_class_name
    // printf("Registered for %s\n", a);
    SHOPPING_CART_INDEX++;
    int i = 0;
    while (i < MAX_SHOPPING_CART_ENTRIES)
    {
        if (SHOPPING_CART[i] == NULL)
        {
            SHOPPING_CART[i] = a;
            break;
        }
        i++;
    }
}

void remove_class()
{
    if (SHOPPING_CART_INDEX == 0){
        puts("There aren't any entries yet!");
        return;
    }
    int a = 0;
    puts("Which entry would you like to remove?");
    printf(" > ");
    scanf("%2d", &a);
    --SHOPPING_CART_INDEX;
    free(SHOPPING_CART[a]);
    SHOPPING_CART[a] = NULL;

}

void edit_shopping_cart()
{
    int a = 0;
    puts("Which entry would you like to edit?");
    printf(" > ");
    scanf("%2d", &a);
    if (SHOPPING_CART[a] == NULL)
    {
        puts("That entry is not empty, and cannot be edited");
        return;
    }
    puts("Enter the new class name");
    printf(" > ");
    scanf("%s", SHOPPING_CART[a]);

}

int main(int argc, char ** argv)
{
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    puts("Welcome to the Mythical class-registration system closed beta trial.");
    puts("Please report any issues with registering for classes.");
    puts("Please ignore any and all crashes of the client (WILL NOT FIX).");
    do
    {
        int a = 0;
        print_menu();
        scanf("%2d", &a);

        switch (a)
        {
            case 1:
                register_for_class();
                break;
            case 2:
                edit_shopping_cart();
                break;
            case 3:
                remove_class();
                break;
            case 4:
                exit(0);
                break;
            case 5:
                print_shopping_cart();
                break;
            default:
                break;

        }
    } while ( 1 );
    return 0;
}
