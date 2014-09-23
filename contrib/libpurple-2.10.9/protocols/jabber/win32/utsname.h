#ifndef _SYS_UTSNAME_H
#define _SYS_UTSNAME_H

#ifdef __cplusplus
extern "C" {
#endif

struct utsname
{
  char sysname[20];
  char nodename[20];
  char release[20];
  char version[20];
  char machine[20];
};

int jabber_win32_uname (struct utsname *);
#define uname(utsname) jabber_win32_uname(utsname)

#ifdef __cplusplus
}
#endif

#endif
