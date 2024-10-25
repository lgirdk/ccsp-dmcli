/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/
/*********************************************************************************

    description:

        This is the template file of ssp_main.c for XxxxSsp.
        Please replace "XXXX" with your own ssp name with the same up/lower cases.

  ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"

#define DEBUG_INI_NAME "/etc/debug.ini"
extern char*                                pComponentName;
char                                        g_Subsystem[32]         = {0};
int consoleDebugEnable = 0;
FILE* debugLogFile;

int  cmd_dispatch(int  command)
{
    switch ( command )
    {
        case    'e' :
            CcspTraceInfo(("Connect to bus daemon...\n"));
            {
                char                            CName[256];
                if ( g_Subsystem[0] != 0 )
                {
                    _ansc_sprintf(CName, "%s%s", g_Subsystem, CCSP_COMPONENT_ID_TESTSERVER);
                }
                else
                {
                    _ansc_sprintf(CName, "%s", CCSP_COMPONENT_ID_TESTSERVER);
                }
                ssp_Mbi_MessageBusEngage(CName, CCSP_MSG_BUS_CFG, CCSP_COMPONENT_PATH_TESTSERVER);
            }
            ssp_create();
            ssp_engage();
            break;
        
		case    'm':
	        AnscPrintComponentMemoryTable(pComponentName);
            break;
    
	    case    't':
        	AnscTraceMemoryTable();
           	break;

        case    'c':                
        	ssp_cancel();
            break;

        default:
            break;
    }
    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
	void* tracePtrs[100];
	char** funcNames = NULL;
	int i, count = 0;

	count = backtrace( tracePtrs, 100 );
	backtrace_symbols_fd( tracePtrs, count, 2 );

	funcNames = backtrace_symbols( tracePtrs, count );

	if ( funcNames ) {
            // Print the stack trace
	    for( i = 0; i < count; i++ )
		printf("%s\n", funcNames[i] );

            // Free the string pointers
            free( funcNames );
	}
#endif
#endif
}

static void daemonize(void) {
	switch (fork()) {
	case 0:
		break;
	case -1:
		// Error
		CcspTraceInfo(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
				errno)));
		exit(0);
		break;
	default:
		_exit(0);
	}

	if (setsid() < 	0) {
		CcspTraceInfo(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
		exit(0);
	}
#ifndef  _DEBUG

	int fd;
	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) {
    	signal(SIGINT, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGINT received!\n"));
	exit(0);
    }
    else if ( sig == SIGUSR1 ) {
    	signal(SIGUSR1, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 ) {
    	CcspTraceInfo(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) {
    	signal(SIGCHLD, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) {
    	signal(SIGPIPE, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGPIPE received!\n"));
    }
    else {
    	/* get stack trace first */
    	_print_stack_backtrace();
    	CcspTraceInfo(("Signal %d received, exiting!\n", sig));
    	exit(0);
    }

}


int main(int argc, char* argv[])
{
    BOOL bRunAsDaemon = TRUE;
    int cmdChar = 0;
    int idx = 0;

    extern ANSC_HANDLE bus_handle;
    char *subSys = NULL;  
    DmErr_t err;
    debugLogFile = stderr;

    // Buffer characters till newline for stdout and stderr
    setlinebuf(stdout);
    setlinebuf(stderr);

    for (idx = 1; idx < argc; idx++)
    {
        if ((strcmp(argv[idx], "-subsys") == 0))
        {
            AnscCopyString(g_Subsystem, argv[idx+1]);
        }
        else if (strcmp(argv[idx], "-c") == 0)
        {
            bRunAsDaemon = FALSE;
        }
        else if ((strcmp(argv[idx], "-DEBUG") == 0))
        {
            consoleDebugEnable = 1;
            fprintf(stderr, "DEBUG ENABLE ON \n");
        }
        else if ( (strcmp(argv[idx], "-LOGFILE") == 0) )
        {
            // We assume argv[1] is a filename to open
            debugLogFile = fopen( argv[idx + 1], "a+" );

            /* fopen returns 0, the NULL pointer, on failure */
            if ( debugLogFile == 0 )
            {
                debugLogFile = stderr;
                fprintf(debugLogFile, "Invalid Entry for -LOGFILE input \n" );
            }
            else 
            {
                fprintf(debugLogFile, "Log File [%s] Opened for Writing in Append Mode \n",  argv[idx+1]);
            }
          
            /* Coverity Fix CID:110556 RESOURCE_LEAK */
            fclose(debugLogFile);
        }                  
    }

    pComponentName = CCSP_COMPONENT_NAME_TESTSERVER;

    if ( bRunAsDaemon ) 
        daemonize();

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);

    cmd_dispatch('e');
#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif
    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);
    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));
        exit(1);
    }
    
    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            cmd_dispatch(cmdChar);
        }
    }

	err = Cdm_Term();
	if (err != CCSP_SUCCESS)
	{
	fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
	exit(1);
	}

	ssp_cancel();

    if(debugLogFile)
    {
        fclose(debugLogFile);
    }
    
    return 0;
}
