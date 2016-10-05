#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

void usage() {
	printf("Usage: sshipassist-daemon <path-to-sshipassist>\n");
}

int main(int argc, char const *argv[])
{
	char targetdir[1024];
	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}
	else
		strcpy(targetdir, argv[1]);

	/* Our process ID and Session ID */
	pid_t pid, sid;

	/* Fork off the parent process */       
	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* If we got a good PID, then
	we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Change the file mode mask */
	umask(0);

	/* Open any logs here */
	FILE *logfile = fopen("sshipassist-daemon.log", "w");

	if (logfile == NULL) {
		printf("Error opening file!\n");
		exit(EXIT_FAILURE);
	}
	else {
		const char *text = "Logging started.";
		fprintf(logfile, "INFO: %s\n", text);
		fflush(logfile);
	}

	/* Create a new SID for the child process */
	sid = setsid();

	if (sid < 0) {
		const char *text = "sid is " + sid;
		fprintf(logfile, "FAILURE: %s\n", text);
		fflush(logfile);
		fclose(logfile);
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	// if ((chdir("/")) < 0) {
	// 	const char *text = "Could not chdir.";
	// 	fprintf(logfile, "FAILURE: %s\n", text);
	// 	fflush(logfile);
	// 	exit(EXIT_FAILURE);
	// }

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* The Big Loop */
	if (1) {
		char buffer[1024];
		strcpy(buffer, "cd ");
		strcat(buffer, targetdir);
		strcat(buffer, "; ./server.bash > 'sshipassist-output.txt';");
		fprintf(logfile, "INFO: Executing SSHIPAssist with: %s\n", buffer);
		fflush(logfile);
		// int res = 0;
		int res = system(buffer);
		char* text = "SSHIPAssist stopped with code: ";
		fprintf(logfile, "INFO: %s %i.\n", text, res);
		fflush(logfile);
		// sleep(30); /* wait 30 seconds */
	}

	const char *text = "Exiting daemon.";
	fprintf(logfile, "INFO: %s\n", text);
	fflush(logfile);
	fclose(logfile);
	exit(EXIT_SUCCESS);
}