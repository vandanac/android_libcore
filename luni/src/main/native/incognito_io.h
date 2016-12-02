/*
 * Copyright (c) 2016 Tiramisu
 */
#ifndef INCOGNITO_IO_H_included
#define INCOGNITO_IO_H_included

#define MAX_NUM_FDS_PER_FILE 32
#define MAX_FILE_PATH_SIZE 4096
#define MAX_FILENAME_SIZE 256
#define MAX_DIRNAME_SIZE  3840
#define MAX_FILES_PER_PROCESS 128

enum File_Status {
	VALID = 0,
	DELETED
};

int Incognito_io_init();
void Incognito_io_stop();
int incognito_file_open(const char *pathname, int flags, int *path_set,
						char *incognito_file_path, int incog_pathname_sz,
						int *add_entry, int *update_entry);
int add_file_entry(const char *original_filename, const char *new_filename,
				   File_Status status, int fd);

bool lookup_filename(const char *pathname, char *incognito_pathname,
					 size_t incog_pathname_sz, File_Status *status);
int add_or_update_file_delete_entry(const char *pathname, bool *need_delete,
						   	  	    char *new_filename,
									size_t new_filename_size);
int update_file_status(const char *pathname, File_Status statusa);
#endif // INCOGNITO_IO_H_included
