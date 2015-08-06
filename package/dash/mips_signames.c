#include <signal.h>

/* A translation list so we can be polite to our users. */
const char *const signal_names[NSIG + 1] = {
    "EXIT",
    "HUP",
    "INT",
    "QUIT",
    "ILL",
    "TRAP",
    "ABRT",
    "EMT",
    "FPE",
    "KILL",
    "BUS",
    "SEGV",
    "SYS",
    "PIPE",
    "ALRM",
    "TERM",
    "USR1",
    "USR2",
    "CHLD",
    "PWR",
    "WINCH",
    "URG",
    "IO",
    "STOP",
    "TSTP",
    "CONT",
    "TTIN",
    "TTOU",
    "VTALRM",
    "PROF",
    "XCPU",
    "XFSZ",
    "RTMIN",
    "RTMIN+1",
    "RTMIN+2",
    "RTMIN+3",
    "RTMIN+4",
    "RTMIN+5",
    "RTMIN+6",
    "RTMIN+7",
    "RTMIN+8",
    "RTMIN+9",
    "RTMIN+10",
    "RTMIN+11",
    "RTMIN+12",
    "RTMIN+13",
    "RTMIN+14",
    "RTMIN+15",
    "RTMIN+16",
    "RTMIN+17",
    "RTMIN+18",
    "RTMIN+19",
    "RTMIN+20",
    "RTMIN+21",
    "RTMIN+22",
    "RTMIN+23",
    "RTMIN+24",
    "RTMIN+25",
    "RTMIN+26",
    "RTMIN+27",
    "RTMIN+28",
    "RTMIN+29",
    "RTMIN+30",
    "RTMIN+31",
    "RTMIN+32",
    "RTMIN+33",
    "RTMIN+34",
    "RTMIN+35",
    "RTMIN+36",
    "RTMIN+37",
    "RTMIN+38",
    "RTMIN+39",
    "RTMIN+40",
    "RTMIN+41",
    "RTMIN+42",
    "RTMIN+43",
    "RTMIN+44",
    "RTMIN+45",
    "RTMIN+46",
    "RTMIN+47",
    "RTMIN+48",
    "RTMAX-47",
    "RTMAX-46",
    "RTMAX-45",
    "RTMAX-44",
    "RTMAX-43",
    "RTMAX-42",
    "RTMAX-41",
    "RTMAX-40",
    "RTMAX-39",
    "RTMAX-38",
    "RTMAX-37",
    "RTMAX-36",
    "RTMAX-35",
    "RTMAX-34",
    "RTMAX-33",
    "RTMAX-32",
    "RTMAX-31",
    "RTMAX-30",
    "RTMAX-29",
    "RTMAX-28",
    "RTMAX-27",
    "RTMAX-26",
    "RTMAX-25",
    "RTMAX-24",
    "RTMAX-23",
    "RTMAX-22",
    "RTMAX-21",
    "RTMAX-20",
    "RTMAX-19",
    "RTMAX-18",
    "RTMAX-17",
    "RTMAX-16",
    "RTMAX-15",
    "RTMAX-14",
    "RTMAX-13",
    "RTMAX-12",
    "RTMAX-11",
    "RTMAX-10",
    "RTMAX-9",
    "RTMAX-8",
    "RTMAX-7",
    "RTMAX-6",
    "RTMAX-5",
    "RTMAX-4",
    "RTMAX-3",
    "RTMAX-2",
    "RTMAX-1",
    "RTMAX",
    (char *)0x0
};
