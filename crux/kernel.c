#include <stdint.h>
#include <stddef.h>
#include "translate.h"
#include "mem/malloc.h"

#define MAXCMDLEN 512

#define NUMENVVARS 16

char *envvars[NUMENVVARS];
char envvarnames[NUMENVVARS][MAXCMDLEN] = {0};

extern void register_syscall();
extern int putchar(int pch);
extern int puts(char *s);
extern int putqword(uint64_t pch);
extern int32_t readstr(char *buf, int64_t len);
extern int getdirents(int ignore);
extern int catfile(char *filename);
extern void halt();

int32_t strlen(const char *s);
void print_string(const char *str);
int32_t atoi(const char *s);
void print_prompt(void);
int parse_cmd(char *, int32_t);
int strcmp(const char *x, const char *y);
void memset(void *b, int c, int len);
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
int strncmp(const char * s1, const char * s2, size_t n);
char *strstr(const char *s1, const char *s2);
int memcmp(const void * s1, const void * s2,size_t n);
void *memcpy(void *dest, const void *src, size_t n);

char heap[4096] = {0};

void memset(void *b, int c, int len) {
	char *s = b;
	while(len--)
		*s++ = c;
}

void *memcpy(void *dest, const void *src, size_t n) {
	char *dp = dest;
	const char *sp = src;
	while (n--)
		*dp++ = *sp++;
	return dest;
}

char *strstr(const char *s1, const char *s2) {
    size_t n = strlen(s2);
    while(*s1)
        if(!memcmp(s1++,s2,n))
            return s1-1;
    return 0;
}

int memcmp(const void* s1, const void* s2,size_t n) {
	const unsigned char *p1 = s1, *p2 = s2;
	while(n--)
		if( *p1 != *p2 )
			return *p1 - *p2;
		else
			p1++,p2++;
	return 0;
}

int strcmp(const char *x, const char *y) {
	while(*x) {
		if (*x != *y) break;
		x++;
		y++;
	}
	return *(const unsigned char*)x - *(const unsigned char*)y;
}

int strncmp(const char* s1, const char* s2, size_t n) {
    while(n--)
        if(*s1++!=*s2++)
            return *(unsigned char*)(s1 - 1) - *(unsigned char*)(s2 - 1);
    return 0;
}

int32_t atoi(const char *a) {
	int c, sign, offset, n;
	if (a[0] == '-') {  // Handle negative integers
		sign = -1;
	}
	if (sign == -1) {  // Set starting position to convert
		offset = 1;
	}
	else {
		offset = 0;
	}
	n = 0;
	for (c = offset; a[c] != '\0'; c++) {
		if(a[c] == '\n' || a[c] == ' ') {
			break;
		}
		n = n * 10 + a[c] - '0';
	}
	if (sign == -1) {
		n = -n;
	}
	return n;
}

int32_t strlen(const char *s) {
	int32_t x = 0;
	while (s[x] != 0) {
		x++;
	}
	return x;
}
void print_string(const char *str) {
	int32_t s = strlen(str);
	for (int i = 0; i < s; i++) {
		putchar(str[i]);
		//printf("%c", str[i]);
	}
}

#define IS_ALPHA(c) (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#define TO_UPPER(c) ((c) & 0xDF)
int isupper(int ch)
{
    return (ch >= 'A' && ch <= 'Z');  // ASCII only - not a good implementation!
}
int islower(int ch)
{
    return (ch >= 'a' && ch <= 'z');  // ASCII only - not a good implementation!
}
int tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c +'a'-'A';
    else
        return c;
}
char *strcasestr(const char *haystack,
		 const char *needle)
{
  unsigned char lcn, ucn;
  unsigned i;

  if (haystack == NULL || needle == NULL)
    return NULL;

  lcn = ucn = needle[0];
  if (isupper(lcn))
    lcn = tolower(lcn);
  else if (islower(ucn))
    ucn = TO_UPPER(ucn);

  if (lcn == 0)
    return (char *)haystack;

  while (haystack[0] != 0) {
    if (lcn == haystack[0] || ucn == haystack[0]) {
      for (i = 1; ; i++) {
	char n = needle[i], h = haystack[i];
	if (n == 0)
	  return (char *)haystack;
	if (h == 0)
	  return NULL;
	if (isupper(n)) n = tolower(n);
	if (isupper(h)) h = tolower(h);
	if (n != h)
	  break;
      }
    }
    haystack++;
  }

  return NULL;		/* Not found */
}

void print_prompt(void) {
	print_string("[RTOoOS> ");
}

int parse_cmd(char *cmd, int32_t numchar) {
	int32_t len = strlen(cmd);
	if (len > MAXCMDLEN) {
		return -1;
	}
	if (cmd[len - 1] == '\n') {
		cmd[len - 1] = 0;
	}
	if (!strcmp("help", cmd)) {
		puts("help text TODO!");
	} else if (!strcmp("ls", cmd)) {
		getdirents(0);
	} else if (!strcmp("id", cmd)) {
		puts("uid=0(root) gid=0(wheel) groups=0(wheel)");
	} else if (!strncmp("cat ", cmd, strlen("cat "))) {
		if (strlen(cmd) <= 4) {
			puts("no file to cat");
			return 0;
		}
		if (strcasestr(&cmd[4], "honcho")) {
			puts("reading hypervisor blocked by kernel!!");
		//if (!strncmp(&cmd[4], "honcho", strlen("honcho"))) {
		//	puts("reading hypervisor blocked by kernel!");
		} else {
			catfile(&cmd[4]);
		}
	} else if(!strncmp("export ", cmd, strlen("export "))) {
		char *s = &cmd[strlen("export ")];
		char *eql = NULL;
		int has_eql = 0;
		int is_set = 0;
		for (int i = 0; i < strlen(s); i++) {
			if (s[i] == '=') {
				eql = &s[i + 1];
				s[i] = '\x00';
				break;
			}
		}
		// the var already exists, update it
		for (int i = 0; i < NUMENVVARS; i++) {
			int envidx = 0;
			if (strlen(envvarnames[i])) {
				if (!strcmp(envvarnames[i], s)) {
					numchar = numchar - strlen(s) - strlen("export");
					int expand = 0;
					for (int j = 0; j < numchar; j++, envidx++) {
						if (eql[j] == '$') {
							for (int k = 0; k < NUMENVVARS; k++) {
								if (!strncmp(&eql[j+1], envvarnames[k], strlen(envvarnames[k]))) {
									for (int m = 0; m < strlen(envvars[k]); m++) {
										envvars[i][envidx++] = envvars[k][m];
									}
									j += strlen(envvars[k]);
									break;
								}
							}
						}
						envvars[i][envidx] = eql[j];
					}
				}
			}
		}
		// new one
		if (!is_set) {
			int envidx = 0;
			for (int i = 0; i < NUMENVVARS; i++) {
				if (strlen(envvarnames[i]) == 0) {
					// it's empty, let's take it!
					memcpy(envvarnames[i], s, strlen(s));
					envvars[i] = malloooc(MAXCMDLEN - strlen(s) - strlen("export ") + 1);
					numchar = MAXCMDLEN - strlen(s) - strlen("export ");
					for (int j = 0; j < numchar; j++, envidx++) {
						if (eql[j] == '$') {
							for (int k = 0; k < NUMENVVARS; k++) {
								if (!strncmp(&eql[j+1], envvarnames[k], strlen(envvarnames[k]))) {
									for (int m = 0; m < strlen(envvars[k]); m++) {
										envvars[i][envidx++] = envvars[k][m];
									}
									j += strlen(envvars[k]);
									break;
								}
							}
						}
						envvars[i][envidx] = eql[j];
					}
					break;
				}
			}
		}
	} else if(!strcmp("env", cmd)) {
		for (int i = 0; i < NUMENVVARS; i++) {
			if (strlen(envvarnames[i]) != 0) {
				print_string(envvarnames[i]);
				print_string("=");
				print_string(envvars[i]);
				print_string("\n");
			}
		}
	} else if (!strcmp("exit", cmd)) {
		halt();
	} else if (!strncmp("unset ", cmd, strlen("unset "))) {
		char *s = &cmd[6];
		for (int i = 0; i < NUMENVVARS; i++) {
			if (strlen(envvarnames[i]) != 0) {
				if (!strcmp(envvarnames[i], s)) {
					envvarnames[i][0] = '\x00';
					//bzero(envvarnames[i], MAXCMDLEN);
					ooofree(envvars[i]);
					break;
				}
			}
		}
	} else {
		puts("command not found, press \"help\" for help!");
	}
	return 0;
}

int kernel_main(void *addr, uint64_t len, uint64_t argc, char *argv[0]) {
	char cmd[MAXCMDLEN];
	malloooc_init(heap, sizeof(heap));
	puts("CS420 - Homework 1");
	puts("Student: Kurt Mandl");
	puts("Submission Stardate 37357.84908798814");

	for (;;) {
		bzero(cmd, MAXCMDLEN);
		print_prompt();
		int32_t nchar = readstr(cmd, MAXCMDLEN - 1);
		parse_cmd(cmd, nchar);
	}
	return 0;
}
