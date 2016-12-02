#include "cutils/log.h"
#include "incognito_io.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>


struct OpenedFile {
	char original_filename[MAX_FILE_PATH_SIZE];
	char incog_filename[MAX_FILE_PATH_SIZE];
	File_Status status; 
	int fd;
};

struct DirectoryInfo {
	char path[MAX_FILE_PATH_SIZE];
};

//XXX: TODO Make thread safe update to the data structure.
struct IncognitoState {
	struct OpenedFile *opened_files;	
	struct DirectoryInfo *opened_dirs;
	int opened_files_cnt;
	int opened_dirs_cnt;
	int total_files_cnt;
};

static struct IncognitoState global_incognito_state;
bool incognito_mode = false;
pthread_mutex_t global_lock=PTHREAD_MUTEX_INITIALIZER;

int remove_file(char *pathname) {
	int rc;

	rc = remove(pathname);
	if (rc) {
		ALOGE("Tiramisu: Error: could not delete the file: errno=%d", errno);
		return errno;
	}

	return rc;
}

int remove_all_incognito_files() {
	int i;
	int rc = 0;
	ALOGE("Tiramisu: Error : Removing all files %d", global_incognito_state.opened_files_cnt); 
	for (i = 0; i < global_incognito_state.opened_files_cnt; i++) {
		struct OpenedFile *file = &global_incognito_state.opened_files[i];
		ALOGE("Tiramisu: Error: deleting file %s %d\n", file->incog_filename, file->status);
		if (file->status == DELETED) {
			continue;
		}
		rc = remove_file(file->incog_filename);
		if (rc) {
			break;
		}
	}
	return rc;
}

void remove_all_directory() {
	int i;

	for (i = global_incognito_state.opened_dirs_cnt - 1; i >= 0; i--) {
		struct DirectoryInfo *dir = &global_incognito_state.opened_dirs[i];
		if (dir->path[0] != '\0' && remove(dir->path)) {
			ALOGE("Tiramisu: Could not remove directory %s", dir->path);
		}
	}
}

int Incognito_io_init() {
    // Check if the global incognito state is already inited for the process.
    // If the state is inited, return.
	if (incognito_mode) {
		ALOGE("Tiramisu: Incognito session for the app exists, restart the app to start a new incognito session");
		return 0;
	}

	// Allocate memory.
	global_incognito_state.opened_files = (struct OpenedFile *)
		calloc(MAX_FILES_PER_PROCESS, sizeof(struct OpenedFile));
	if (global_incognito_state.opened_files == NULL) {
		return ENOMEM;
	}
	global_incognito_state.opened_dirs = (struct DirectoryInfo *)
		calloc(MAX_FILES_PER_PROCESS, sizeof(struct DirectoryInfo));
	if (global_incognito_state.opened_dirs == NULL) {
		return ENOMEM;
	}
	global_incognito_state.total_files_cnt = MAX_FILES_PER_PROCESS;
	global_incognito_state.opened_files_cnt = 0;
	global_incognito_state.opened_dirs_cnt = 0;
	incognito_mode = true;
	ALOGE("Tiramisu: Incognito state init successful");
    return 0;
}

void Incognito_io_stop() {
	if (!incognito_mode) {
		ALOGE("Tiramisu: Error: Incognito_io_stop called without init\n"); 
		return;
	}

	remove_all_incognito_files();
	remove_all_directory();
	free(global_incognito_state.opened_files);
	global_incognito_state.opened_files = NULL;
	global_incognito_state.total_files_cnt = 0;
	global_incognito_state.opened_files_cnt = 0;
	incognito_mode = false;
	ALOGE("Tiramisu: Incognito state deinit successful");
	return;
}

int get_incognito_filename(char *old_filename, char *new_filename,
                      size_t new_filename_size) {
    strcpy(new_filename, "INCOGNITO_TIRAMISU_");
    int len = strlen(new_filename);
    int old_file_len = strlen(old_filename);

    // These checks can be disabled if performance is an issue.
    if ((old_file_len + len + 1) > (int) new_filename_size) {
        ALOGE("Tiramisu: Error: Not able to generate new filename, buffer too small");
        return ENOMEM;
    }

    strcpy(new_filename+len, old_filename);

    return 0;
}

int combine_dirname_filename(char *directory_name, char *filename,
    char *path_buf, size_t path_buf_size) {

    int dirlen = strlen(directory_name);
    int filelen = strlen(filename);

    // Check if buffer is big enough.
    if ((dirlen + filelen + 1) > (int) path_buf_size) {
        //ALOGE("Tiramisu: Error: Not able to generate new path, buffer too small");
        return ENOMEM;
    }

    // Copy directory path.
    strcpy(path_buf, directory_name);

    strcpy(path_buf + dirlen, "/");

    // Copy filename to path.
    strcpy(path_buf + dirlen + 1, filename);

    return 0;
}

int parse_path_get_filename_dirname(const char *path, char *filename, size_t filename_sz,
									char *dirname, size_t dirname_sz) {
	char tmp_path[MAX_FILE_PATH_SIZE];
    int len = strlen(path);
	int i;

	// copy the path to temp var.
	strcpy(tmp_path, path);

	// Remove all '/' at the end 
    i = len - 1;
    while (tmp_path[i] == '/') {
        i--;
    }
    tmp_path[i+1] = '\0';

	// Get filename
    while (tmp_path[i] != '/') {
        i--;
    }

	if (strlen(tmp_path+i+1) > filename_sz) {
		ALOGE("Tiramisu: Error: Buffer is too small to copy filename");
		return ENOMEM;
	}
    strcpy(filename, tmp_path+i+1);
    tmp_path[i] = '\0';

	if (strlen(tmp_path) > dirname_sz) {
		ALOGE("Tiramisu: Error: Buffer is too small to copy filename");
		return ENOMEM;
	}
    strcpy(dirname, tmp_path);

	return 0;
}

int parse_path_get_incognito_file_path(const char *path, char *incognito_file_path,
									   size_t incognito_file_path_sz) {
	char filename[MAX_FILENAME_SIZE];
	char dirname[MAX_DIRNAME_SIZE];
	char incognito_filename[MAX_FILENAME_SIZE];
	int rc;

	rc = parse_path_get_filename_dirname(path, filename, MAX_FILENAME_SIZE,
										 dirname, MAX_DIRNAME_SIZE);
	if (rc) {
		return rc;
	}

	rc = get_incognito_filename(filename, incognito_filename, MAX_FILENAME_SIZE);
	if (rc) {
		return rc;
	}

	rc = combine_dirname_filename(dirname, incognito_filename,
								 incognito_file_path, incognito_file_path_sz);
	return rc;
}

template <typename T>
void ignore_var(T &&) {
}

int make_file_copy(const char *original_filename, char *new_filename) {
	int orig_file_fd, new_file_fd;
    struct stat file_stat;
	int size;

	ALOGE("Tiramisu: Triggering a copy");

    orig_file_fd = open(original_filename, O_RDONLY);
    if (orig_file_fd< 0) {
        ALOGE("Tiramisu: Error: File open failed: %s \n", original_filename);
        return errno;
    }

    new_file_fd = open(new_filename, O_CREAT|O_RDWR,
        S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
    if (new_file_fd < 0) {
        ALOGE("Tiramisu: Error: File open failed: %s \n", new_filename);
        return errno;
    }

    if (stat(original_filename, &file_stat) != 0) {
		ALOGE("Tiramisu: Error: stat failed for file %s\n", original_filename);
		return EINVAL;
	}

    ALOGE("Tiramisu: copying file of size: %d\n", (int)file_stat.st_size);
    char buf[16384];

    size = (int) file_stat.st_size;
    while (size) {
        size_t rd_size = (size > 16384)? 16384 : size;
        rd_size = read(orig_file_fd, buf, rd_size);
        size_t wr_size = write(new_file_fd, buf, rd_size);
        if (rd_size != wr_size) {
            ALOGE("ERROR: Write failed: write request size: %zu written bytes: %zu\n", rd_size, wr_size);
            return 1;
        }
        if (rd_size < 16384) break;
        size -= rd_size;
    }

	close(orig_file_fd);
    close(new_file_fd);

	return 0;
}

void debug_print_flags(int flags) {
	ALOGE("O_CREAT: 0x%x O_APPEND 0x%x O_TRUNC 0x%x O_WRONLY 0x%x O_RDONLY 0x%x O_RDWR 0x%x O_ASYNC 0x%x\n",
				O_CREAT, O_APPEND, O_TRUNC, O_WRONLY, O_RDONLY, O_RDWR, O_ASYNC);
	ALOGE("O_CREAT: 0x%x O_APPEND 0x%x O_TRUNC 0x%x O_WRONLY 0x%x O_RDONLY 0x%x O_RDWR 0x%x O_ASYNC 0x%x\n",
				flags & O_CREAT, flags & O_APPEND, flags & O_TRUNC, flags & O_WRONLY,
				flags & O_RDONLY, flags & O_RDWR, flags & O_ASYNC);
}

bool lookup_filename(const char *pathname, char *incognito_pathname,
					 size_t incog_pathname_sz, File_Status *status) {
	int i;

	pthread_mutex_lock(&global_lock);
	for (i = 0; i < global_incognito_state.opened_files_cnt; i++) {
		struct OpenedFile *file = &global_incognito_state.opened_files[i];
		if (strcmp(file->original_filename, pathname) == 0) {
			if (incognito_pathname && 
				(incog_pathname_sz >= MAX_FILE_PATH_SIZE)) {
				strcpy(incognito_pathname, file->incog_filename);
			} else {
				ALOGE("Tiramisu: lookup did not copy file because\n");
			} 
			*status = file->status;

			pthread_mutex_unlock(&global_lock);
			return true;
		}
	}
	pthread_mutex_unlock(&global_lock);

	return false;
}

int add_file_entry(const char *original_filename, const char *new_filename,
				   File_Status status, int fd) {
	pthread_mutex_lock(&global_lock);
	if (global_incognito_state.opened_files_cnt == global_incognito_state.total_files_cnt) {
		ALOGE("Tiramisu: Incognito table is full\n");
		pthread_mutex_unlock(&global_lock);
		return ENOMEM;
	}

	struct OpenedFile *file = &global_incognito_state.opened_files[global_incognito_state.opened_files_cnt];
	strcpy(file->original_filename, original_filename);
	strcpy(file->incog_filename, new_filename);
	file->status = status;
	file->fd = fd; 
	global_incognito_state.opened_files_cnt++;
	pthread_mutex_unlock(&global_lock);
	ALOGE("Tiramisu: Added file entry for %s\n", original_filename);

	return 0;
}

int incognito_file_open(const char *pathname, int flags, int *path_set,
						char *incognito_file_path, int incog_pathname_sz,
						int *add_entry, int *update_entry) {
	// Make a copy of the original file only the file is being opened in
	// append mode
	// 1. If the file is being created in incognito mode,
	int rc = 0;

	*path_set = 0;
	*add_entry = 0;
	*update_entry = 0;

	if (incog_pathname_sz < MAX_FILE_PATH_SIZE) {
		return ENOMEM;
	} 

	// If it's not write operation, return.
	if (!((flags & O_WRONLY) || (flags & O_RDWR))) {
		// Search incognito files and return if files 
		File_Status status;
		*path_set = lookup_filename(pathname, incognito_file_path,
									incog_pathname_sz, &status);
		return 0;
	}

	debug_print_flags(flags);

	rc = parse_path_get_incognito_file_path(pathname, incognito_file_path,
											MAX_FILE_PATH_SIZE);
	if (rc) {
		return rc;
	}
	*path_set = 1;

	ALOGE("Incognito: DEBUG: pathname %s incognito filename %s\n",
						pathname, incognito_file_path);

	// If it's not append or truncate, return.
	if (!((flags & O_APPEND) || (flags & O_TRUNC))) return 0;


	File_Status status;
	// If the file is already there in incognito list, then return.
	if (lookup_filename(pathname, NULL, 0, &status)) {
		// If the file is deleted, then a new entry should be added. 
		if (status == DELETED) {
			*update_entry = 1;
		};

		return 0;
	}

	struct stat file_stat;
    if ((flags & O_TRUNC) && (stat(pathname, &file_stat) != 0)) {
        if (errno != ENOENT) {
			ALOGE("Tiramisu: errno is not ENOENT %s\n", pathname);
			return EINVAL;
		}
    } else {
		// Make a copy of the file.
		rc = make_file_copy(pathname, incognito_file_path);
	}

	// Add an entry in global incognito state.
	*add_entry = 1;

	return rc;
}

int add_new_file_delete_entry(const char *pathname) {
	char incognito_file_path[MAX_FILE_PATH_SIZE];
	int rc = 0;
	int idx = global_incognito_state.opened_files_cnt++;
	struct OpenedFile *file = &global_incognito_state.opened_files[idx];

	rc = parse_path_get_incognito_file_path(pathname, incognito_file_path,
											MAX_FILE_PATH_SIZE);
	if (rc) {
		return rc;
	}

	strcpy(file->original_filename, pathname);
	file->status = DELETED;
	strcpy(file->incog_filename, incognito_file_path);
	ALOGE("Tiramisu: New entry has been added for %s", pathname);

	return rc;
}

bool lookup_directory(const char *pathname) {
	int i;

	for (i = global_incognito_state.opened_dirs_cnt - 1; i >= 0; i--) {
		struct DirectoryInfo *dir = &global_incognito_state.opened_dirs[i];
		if (dir->path[0] != '\0' &&
					strcmp(pathname, dir->path) == 0) {
			return true;
		}
	}

	return false;
}

void delete_directory_entry(const char *pathname) {
	int i;

	for (i = 0; i < global_incognito_state.opened_dirs_cnt; i++) {
		struct DirectoryInfo *dir = &global_incognito_state.opened_dirs[i];

		if (strcmp(dir->path, pathname) == 0) {
			dir->path[0] = '\0';	
			ALOGE("Tiramisu: Deleting the entry %s", pathname);
			break;
		}
	}
	return;
}

/**
 * If user is deleting a file, then one of the following actions should be
 * taken.
 * 1. If file was created before incognito session started and if the file
 * was not modified in incognito session, then file should not be deleted.
 * A new entry should be added to the global state which marks the file status
 * as DELETED. 
 * 2. If file was created before incognito session started and if the file
 * was modified during the incognito session, then new file should be deleted.
 * Existing entry in the global should be updated with DELETED status.
 * 3. If file was created during this incognito session, then the file should
 * be deleted. The entry in the global state should be removed.
 *
 * Function returns: need_delete is true and fills new_filename if a file needs
                     to be deleted. Otherwise, sets need_delete as false.
 */
int add_or_update_file_delete_entry(const char *pathname, bool *need_delete,
						   	  	    char *new_filename,
									size_t new_filename_size) {
	int rc = 0, i;
	*need_delete = false;

	if (new_filename_size < MAX_FILE_PATH_SIZE) {
		ALOGE("Tiramisu: Filename buffer is too small, exiting");
		return ENOMEM;
	}

	pthread_mutex_lock(&global_lock);
	// Check if the file exists in the global state.
	for (i = 0; i < global_incognito_state.opened_files_cnt; i++) {
		struct OpenedFile *file = &global_incognito_state.opened_files[i];
		// File exists in the global state, then update the status.
		if (strcmp(file->original_filename, pathname) == 0) {
			file->status = DELETED;
			*need_delete = true;
			strcpy(new_filename, file->incog_filename);
			break;
		}
	}

	// File does not exist in the global state, add an entry for the file.
	if (!(*need_delete)) {
		ALOGE("Adding a new entry for delete");
		rc = add_new_file_delete_entry(pathname);
	} else if (lookup_directory(pathname)) {
		*need_delete = true;
		delete_directory_entry(pathname);
	} else {
		ALOGE("Not adding a new entry for delete");
	}
	pthread_mutex_unlock(&global_lock);

	return rc;
}

int update_file_status(const char *pathname, File_Status status) {
	int i;
	int rc = 1;

	pthread_mutex_lock(&global_lock);
	for (i = 0; i < global_incognito_state.opened_files_cnt; i++) {
		struct OpenedFile *file = &global_incognito_state.opened_files[i];
		// Update the status of the existing file entry.
		if (strcmp(file->original_filename, pathname) == 0) {
			ALOGE("Tiramisu: Updating the status for the file %s, current status %d, new status %d",
				  pathname, file->status, status);
			file->status = status;
			rc = 0;
			break;
		}
	}
	pthread_mutex_unlock(&global_lock);

	return rc;
}

void add_directory_entry(const char *pathname) {
	int idx = global_incognito_state.opened_dirs_cnt++;
	struct DirectoryInfo *dir = &global_incognito_state.opened_dirs[idx];

	strcpy(dir->path, pathname);
}
