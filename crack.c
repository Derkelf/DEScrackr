/*
 * Cracks DES passwords with brute force 
 */
#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define C_NAME "./crack"          //command name
#define S_LIMIT 100000000         //words limit
#define C_LIMIT 100               //characters limit  
#define W_LIST "word_list"        //wordlist file

int p_crack(char* pwd, const char* passwd);
void yell(void);

int main(int argc, char* argv[])
{
    //lets yell at the user if there are too many or no arguments at all
    if (argc > 2 || argc == 1)
    {
        yell();
        return 1;
    }

    char password[C_LIMIT];

    if(p_crack(password, argv[1]))
        printf("Cracked password: %s\n", password);
    else
        printf("No passwords were found.\n");
    
    return 0;
}

int p_crack(char* pwd, const char* passwd)
{
    char c_password[C_LIMIT], salt[2]; 

    //the salt are the first 2 chars in the encrypted passwd
    for (int i = 0; i < 2; i++)
        salt[i] = passwd[i];

    char words[C_LIMIT] = {'\0'};
    FILE* w_list = fopen(W_LIST, "r");
    if(w_list == NULL)
    {
        printf("ERROR: Couldn't open the wordlist file \'%s\'\n"
                "Please verify that the file exist and run the program again.\n", W_LIST); 
        exit(EXIT_FAILURE);
    }
    else
    {
        //load word number i in the file to the string words
        for(int i = 0; fgets(words, C_LIMIT, w_list) != NULL && i < S_LIMIT; i++)
        {
            words[strlen(words) - 1] = '\0';   //removes the '\n' char at the end that fgets writes 
            
            //encrypts the current password in words
            strcpy(c_password, crypt(words, salt)); 
                
            //debug
            printf("Word: %-20s" "%10s           N* %d\n", words, c_password, i + 1);

            //if the encrypted c_password and the passwd we want to crack are the same, that means words is the cracked password 
            if (strcmp(c_password,  passwd) == 0) 
            {
                //show processed words
                printf("\nNumber of words processed:%d\n", i + 1);

                strcpy(pwd,  words);
                
                fclose(w_list);
                
                return 1;               //we succeeded
            }

        }
    }

    fclose(w_list);

    //if we didn't find any password lets return 0 
    return 0;
}

void yell(void)
{
    printf("That's not how you should use this program!\n"
            "How to use: %s [EncryptedPassword]\n"
            "e.g.:%s 50JkB0IlGZ0mw\n", C_NAME, C_NAME);
}
