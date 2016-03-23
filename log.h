/**
 * @file log.h
 *
 * Log system for debugging.
 *
 * @version $201201101154$
 * @author "Wei-Tsung Lin" <fasthall@gmail.com>
 * @note Copyright(c) 2012., all rights reserved.
 */
#ifndef LOG_H
#define LOG_H

#define LOG_FILENAME "log"

FILE *logfile;
char logString[65536];
void logInitialize(void);
void logClose(void);
void logPush();

#endif
