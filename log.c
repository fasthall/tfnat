/**
 * @file log.c
 *
 * Log system for debugging.
 *
 * @version $201201101154$
 * @author "Wei-Tsung Lin" <fasthall@gmail.com>
 * @note Copyright(c) 2012., all rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

/* initialize log system */
void logInitialize(void) {
	if ((logfile = fopen(LOG_FILENAME, "w")) == NULL) {
		fprintf(stderr, "Cannot open log file.\n");
	}
}

/* close the log file */
void logClose(void) {
	if (logfile != NULL) {
		fclose(logfile);
	}
}

/* push the logged message */
void logPush(void) {
	if (logfile != NULL) {
		fprintf(logfile, "%s", logString);
		fflush(logfile);
		strcpy(logString, "");
	}
}

