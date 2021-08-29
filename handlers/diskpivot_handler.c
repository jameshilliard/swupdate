/*
 * Copyright (C) 2021
 * James Hilliard <james.hilliard1@gmail.com>
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <util.h>
#include <handler.h>
#include <blkid/blkid.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <dirent.h>
#include <systemd/sd-bus.h>
#include <pwd.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

void diskpivot_handler(void);

struct procs {
	pid_t pid;
	uid_t uid;
	char access;
	char proc_type;
	char *username;
	char *command;
	struct procs *next;
};

struct names {
	char *filename;
	unsigned char name_space;
	struct stat st;
	struct procs *matched_procs;
	struct names *next;
};

struct inode_list {
	struct names *name;
	dev_t	device;
	ino_t	inode;
	struct inode_list *next;
};

struct device_list {
	struct names *name;
	dev_t	device;
	struct device_list *next;
};

struct unixsocket_list {
	char *sun_name;
	ino_t	inode;
	ino_t	net_inode;
	dev_t	dev;
	struct unixsocket_list *next;
};

struct mount_list {
	char *mountpoint;
	struct mount_list *next;
};

static dev_t find_net_dev(void)
{
	int skt;
	struct stat st;

	if ((skt = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		ERROR("Cannot open a network socket.");
		return -1;
	}
	if (fstat(skt, &st) != 0) {
		ERROR("Cannot find socket's device number.");
		close(skt);
		return -1;
	}
	close(skt);
	return st.st_dev;
}

static void
add_device(struct device_list **dev_list, struct names *this_name, dev_t device)
{
	struct device_list *dev_tmp, *dev_head;
#ifdef DEBUG
	TRACE("add_device(%s, %u)", this_name->filename,
		(unsigned int)device);
#endif				/* DEBUG */

	if ((dev_tmp =
				 (struct device_list *)malloc(sizeof(struct device_list))) == NULL)
		return;
	dev_head = *dev_list;
	dev_tmp->name = this_name;
	dev_tmp->device = device;
	dev_tmp->next = dev_head;
	*dev_list = dev_tmp;
}

static int
parse_mounts(struct names *this_name, struct device_list **dev_list)
{
	dev_t match_device;

	if (S_ISBLK(this_name->st.st_mode))
		match_device = this_name->st.st_rdev;
	else
		match_device = this_name->st.st_dev;
	add_device(dev_list, this_name, match_device);
	return 0;
}


static void
debug_match_lists(struct names *names_head, struct inode_list *ino_head,
				  struct device_list *dev_head)
{
	struct names *nptr;
	struct inode_list *iptr;
	struct device_list *dptr;

	INFO("Specified Names:");
	for (nptr = names_head; nptr != NULL; nptr = nptr->next) {
		INFO("\t%s %c", nptr->filename, nptr->name_space);
	}
	INFO("Inodes:");
	for (iptr = ino_head; iptr != NULL; iptr = iptr->next) {
		INFO("  Dev:%0lx Inode:(%0ld) 0x%0lx => %s",
				(unsigned long)iptr->device, (unsigned long)iptr->inode,
				(unsigned long)iptr->inode, iptr->name->filename);
	}
	INFO("Devices:");
	for (dptr = dev_head; dptr != NULL; dptr = dptr->next) {
		INFO("\tDev:%0lx", (unsigned long)dptr->device);
	}
}

static uid_t getpiduid(const pid_t pid)
{
	char *pathname;
	struct stat st;

	if (asprintf(&pathname, "/proc/%d", pid) < 0)
		return 0;
	if (stat(pathname, &st) != 0) {
		free(pathname);
		return 0;
	}
	free(pathname);
	return st.st_uid;
}


static struct stat *get_pidstat(const pid_t pid, const char *filename)
{
	char pathname[PATH_MAX];
	struct stat *st;

	if ((st = (struct stat *)malloc(sizeof(struct stat))) == NULL)
		return NULL;
	snprintf(pathname, PATH_MAX-1, "/proc/%d/%s", pid, filename);
	if (stat(pathname, st) != 0) {
		free(st);
		return NULL;
	}
	return st;
}

#define PTYPE_NORMAL 0
#define PTYPE_MOUNT 1
#define PTYPE_KNFSD 2
#define PTYPE_SWAP 3

#define COMM_LEN 64

/* Adds a normal process only */
static void
add_matched_proc(struct names *name_list, const pid_t pid, const uid_t uid,
				 const char access)
{
	struct procs *pptr, *last_proc;
	char *pathname;
	char cmdname[101], *cptr;
	int cmdlen;
	FILE *fp;

	last_proc = NULL;
	for (pptr = name_list->matched_procs; pptr != NULL; pptr = pptr->next) {
		last_proc = pptr;
		if (pptr->pid == pid) {
			pptr->access |= access;
			return;
		}
	}
	/* Not found */
	if ((pptr = (struct procs *)malloc(sizeof(struct procs))) == NULL) {
		ERROR("Cannot allocate memory for matched proc: %s", strerror(errno));
		return;
	}
	pptr->pid = pid;
	pptr->uid = uid;
	pptr->access = access;
	pptr->proc_type = PTYPE_NORMAL;
	pptr->next = NULL;
	/* set command name */
	pptr->command = NULL;

	fp = NULL;
	pathname = NULL;
	if ((asprintf(&pathname, "/proc/%d/stat", pid) > 0) &&
		((fp = fopen(pathname, "r")) != NULL) &&
		(fscanf(fp, "%*d (%100[^)]", cmdname) == 1))
		if ((pptr->command = (char *)malloc(COMM_LEN + 1)) != NULL) {
			cmdlen = 0;
			for (cptr = cmdname; cmdlen < COMM_LEN && *cptr;
				 cptr++) {
				if (isprint(*cptr))
					pptr->command[cmdlen++] = *cptr;
				else if (cmdlen < (COMM_LEN - 4))
					cmdlen +=
							sprintf(&(pptr->command[cmdlen]),
									"\\%03o", *cptr);
			}
			pptr->command[cmdlen] = '\0';
		}
	if (last_proc == NULL)
		name_list->matched_procs = pptr;
	else
		last_proc->next = pptr;
	if (pathname)
		free(pathname);
	if (fp)
		fclose(fp);
}

#define ACCESS_CWD 1
#define ACCESS_EXE 2
#define ACCESS_FILE 4
#define ACCESS_ROOT 8
#define ACCESS_MMAP 16
#define ACCESS_FILEWR 32

static void
check_dir(const pid_t pid, const char *dirname, struct device_list *dev_head,
		  struct inode_list *ino_head, const uid_t uid, const char access,
		  struct unixsocket_list *sockets, dev_t netdev)
{
	DIR *dirp;
	dev_t thedev;
	struct dirent *direntry;
	struct inode_list *ino_tmp;
	struct device_list *dev_tmp;
	struct unixsocket_list *sock_tmp;
	struct stat st, lst;
	char *dirpath;
	char filepath[PATH_MAX];
	char real_filepath[PATH_MAX];

	if (asprintf(&dirpath, "/proc/%d/%s", pid, dirname) < 0)
		return;
	if ((dirp = opendir(dirpath)) == NULL) {
		free(dirpath);
		return;
	}
	free(dirpath);

	while ((direntry = readdir(dirp)) != NULL) {
		if (direntry->d_name[0] < '0' || direntry->d_name[0] > '9')
			continue;

		snprintf(filepath, sizeof filepath - 1, "/proc/%d/%s/%s",
				 pid, dirname, direntry->d_name);

		if (stat(filepath, &st) != 0) {
			if (errno != ENOENT && errno != ENOTDIR) {
				ERROR("Cannot stat file %s: %s", filepath, strerror(errno));
			}
		} else {
			thedev = st.st_dev;
			if (thedev == netdev) {
				for (sock_tmp = sockets; sock_tmp != NULL;
					 sock_tmp = sock_tmp->next) {
					if (sock_tmp->net_inode == st.st_ino) {
						st.st_ino = sock_tmp->inode;
						st.st_dev = sock_tmp->dev;
						thedev = sock_tmp->dev;
						break;
					}
				}
			}
			for (dev_tmp = dev_head; dev_tmp != NULL;
				 dev_tmp = dev_tmp->next) {
				if (thedev != dev_tmp->device)
					continue;

				/* check the paths match if it is not a block device */
				if (! S_ISBLK(dev_tmp->name->st.st_mode)) {
					if (readlink(filepath, real_filepath, PATH_MAX-1) < 0) {
						if (strncmp(dev_tmp->name->filename, filepath, strlen(dev_tmp->name->filename)) != 0)
							continue;
					} else {
						if (strncmp(dev_tmp->name->filename, real_filepath, strlen(dev_tmp->name->filename)) != 0)
							continue;
					}
				}
				if (access == ACCESS_FILE
					&& (lstat(filepath, &lst) == 0)
					&& (lst.st_mode & S_IWUSR)) {
					add_matched_proc(dev_tmp->name,
									 pid, uid,
									 ACCESS_FILEWR |
									 access);
				} else {
					add_matched_proc(dev_tmp->name,
									 pid, uid, access);
				}
			}
			for (ino_tmp = ino_head; ino_tmp != NULL;
				 ino_tmp = ino_tmp->next) {
				if (thedev != ino_tmp->device)
					continue;
				if (!st.st_ino
					&& stat(filepath, &st) != 0) {
					ERROR("Cannot stat file %s: %s",
							filepath, strerror(errno));
					continue;
				}
				if (st.st_ino == ino_tmp->inode) {
					if (access == ACCESS_FILE
						&& (lstat(filepath, &lst) == 0)
						&& (lst.st_mode & S_IWUSR)) {
						add_matched_proc(ino_tmp->name,
										 pid, uid,
										 ACCESS_FILEWR |
										 access);
					} else {
						add_matched_proc(ino_tmp->name,
										 pid, uid,
										 access);
					}
				}
			}
		}
	}			/* while fd_dent */
	closedir(dirp);
}

static void
check_map(const pid_t pid, const char *filename,
		  struct device_list *dev_head, struct inode_list *ino_head,
		  const uid_t uid, const char access)
{
	char *pathname;
	char line[BUFSIZ];
	struct inode_list *ino_tmp;
	struct device_list *dev_tmp;
	FILE *fp;
	unsigned long long tmp_inode;
	unsigned int tmp_maj, tmp_min;
	dev_t tmp_device;

	if (asprintf(&pathname, "/proc/%d/%s", pid, filename) < 0)
		return;
	if ((fp = fopen(pathname, "r")) == NULL) {
		free(pathname);
		return;
	}
	free(pathname);
	while (fgets(line, BUFSIZ, fp)) {
		if (sscanf(line, "%*s %*s %*s %x:%x %lld",
				   &tmp_maj, &tmp_min, &tmp_inode) == 3) {
			tmp_device = tmp_maj * 256 + tmp_min;
			for (dev_tmp = dev_head; dev_tmp != NULL;
				 dev_tmp = dev_tmp->next)
				if (dev_tmp->device == tmp_device)
					add_matched_proc(dev_tmp->name, pid,
									 uid, access);
			for (ino_tmp = ino_head; ino_tmp != NULL;
				 ino_tmp = ino_tmp->next)
				if (ino_tmp->device == tmp_device
					&& ino_tmp->inode == tmp_inode)
					add_matched_proc(ino_tmp->name, pid,
									 uid, access);
		}
	}
	fclose(fp);
}

static void
scan_procs(struct names *names_head, struct inode_list *ino_head,
		   struct device_list *dev_head, struct unixsocket_list *sockets,
		   dev_t netdev)
{
	DIR *topproc_dir;
	struct dirent *topproc_dent;
	struct inode_list *ino_tmp;
	struct device_list *dev_tmp;
	pid_t pid, my_pid;
	uid_t uid;

	if ( (ino_head == NULL) && (dev_head == NULL) )
		return;

	if ((topproc_dir = opendir("/proc")) == NULL) {
		ERROR("Cannot open /proc directory: %s", strerror(errno));
		exit(1);
	}
	my_pid = getpid();
	while ((topproc_dent = readdir(topproc_dir)) != NULL) {
		dev_t cwd_dev, exe_dev, root_dev;
		struct stat *cwd_stat = NULL;
		struct stat *exe_stat = NULL;
		struct stat *root_stat = NULL;

		if (topproc_dent->d_name[0] < '0' || topproc_dent->d_name[0] > '9')	/* Not a process */
			continue;
		pid = atoi(topproc_dent->d_name);
		/* Dont print myself */
		if (pid == my_pid)
			continue;
		uid = getpiduid(pid);

		cwd_stat = get_pidstat(pid, "cwd");
		exe_stat = get_pidstat(pid, "exe");
		root_stat = get_pidstat(pid, "root");
		cwd_dev = cwd_stat ? cwd_stat->st_dev : 0;
		exe_dev = exe_stat ? exe_stat->st_dev : 0;
		root_dev = root_stat ? root_stat->st_dev : 0;

		/* Scan the devices */
		for (dev_tmp = dev_head; dev_tmp != NULL;
			 dev_tmp = dev_tmp->next) {
			if (exe_dev == dev_tmp->device)
				add_matched_proc(dev_tmp->name, pid, uid,
								 ACCESS_EXE);
			if (root_dev == dev_tmp->device)
				add_matched_proc(dev_tmp->name, pid, uid,
								 ACCESS_ROOT);
			if (cwd_dev == dev_tmp->device)
				add_matched_proc(dev_tmp->name, pid, uid,
								 ACCESS_CWD);
		}
		for (ino_tmp = ino_head; ino_tmp != NULL;
			 ino_tmp = ino_tmp->next) {
			if (exe_dev == ino_tmp->device) {
				if (!exe_stat)
					exe_stat = get_pidstat(pid, "exe");
				if (exe_stat
					&& exe_stat->st_dev == ino_tmp->device
					&& exe_stat->st_ino == ino_tmp->inode)
					add_matched_proc(ino_tmp->name, pid,
									 uid, ACCESS_EXE);
			}
			if (root_dev == ino_tmp->device) {
				if (!root_stat)
					root_stat = get_pidstat(pid, "root");
				if (root_stat
					&& root_stat->st_dev == ino_tmp->device
					&& root_stat->st_ino == ino_tmp->inode)
					add_matched_proc(ino_tmp->name, pid,
									 uid, ACCESS_ROOT);
			}
			if (cwd_dev == ino_tmp->device) {
				if (!cwd_stat)
					cwd_stat = get_pidstat(pid, "cwd");
				if (cwd_stat
					&& cwd_stat->st_dev == ino_tmp->device
					&& cwd_stat->st_ino == ino_tmp->inode)
					add_matched_proc(ino_tmp->name, pid,
									 uid, ACCESS_CWD);
			}
		}
		if (root_stat)
			free(root_stat);
		if (cwd_stat)
			free(cwd_stat);
		if (exe_stat)
			free(exe_stat);
#if !defined (__linux__) && !defined (__CYGWIN__)
		check_dir(pid, "lib", dev_head, ino_head, uid, ACCESS_MMAP,
			  sockets, netdev);
		check_dir(pid, "mmap", dev_head, ino_head, uid, ACCESS_MMAP,
			  sockets, netdev);
#endif
		check_dir(pid, "fd", dev_head, ino_head, uid, ACCESS_FILE,
				  sockets, netdev);
		check_map(pid, "maps", dev_head, ino_head, uid, ACCESS_MMAP);

	}			/* while topproc_dent */
	closedir(topproc_dir);
}

#define KNFSD_EXPORTS "/proc/fs/nfs/exports"
#define PROC_MOUNTS "/proc/mounts"
#define PROC_SWAPS "/proc/swaps"

/* Adds a knfsd etc process */
static void
add_special_proc(struct names *name_list, const char ptype, const uid_t uid,
				 const char *command)
{
	struct procs *pptr;

	for (pptr = name_list->matched_procs; pptr != NULL; pptr = pptr->next) {
		if (pptr->proc_type == ptype)
			return;
	}
	if ((pptr = malloc(sizeof(struct procs))) == NULL) {
		ERROR("Cannot allocate memory for matched proc: %s",
				strerror(errno));
		return;
	}
	pptr->pid = 0;
	pptr->uid = uid;
	pptr->access = 0;
	pptr->proc_type = ptype;
	/* Append the special processes */
	pptr->next = name_list->matched_procs;
	name_list->matched_procs = pptr;
	/* set command name */
	pptr->command = strdup(command);
}

static void
scan_knfsd(struct names *names_head, struct inode_list *ino_head,
		   struct device_list *dev_head)
{
	struct device_list *dev_tmp;
	struct inode_list *ino_tmp;
	FILE *fp;
	char line[BUFSIZ];
	char *find_space;
	struct stat st;

	if ( (ino_head == NULL) && (dev_head == NULL) )
		return;


	if ((fp = fopen(KNFSD_EXPORTS, "r")) == NULL) {
#ifdef DEBUG
		TRACE("Cannot open %s", KNFSD_EXPORTS);
#endif
		return;
	}
	while (fgets(line, BUFSIZ, fp) != NULL) {
		if (line[0] == '#') {
			continue;
		}
		if ((find_space = strpbrk(line, " \t")) == NULL)
			continue;
		*find_space = '\0';
		if (stat(line, &st) != 0) {
			continue;
		}
		/* Scan the devices */
		for (dev_tmp = dev_head; dev_tmp != NULL;
			 dev_tmp = dev_tmp->next) {
			if (st.st_dev == dev_tmp->device)
				add_special_proc(dev_tmp->name, PTYPE_KNFSD, 0,
								 line);
		}
		for (ino_tmp = ino_head; ino_tmp != NULL;
			 ino_tmp = ino_tmp->next) {
			if (st.st_dev == ino_tmp->device
				&& st.st_ino == ino_tmp->inode)
				add_special_proc(ino_tmp->name, PTYPE_KNFSD, 0,
								 line);
		}
	}
	fclose(fp);
}

static void
scan_mounts(struct names *names_head, struct inode_list *ino_head,
			struct device_list *dev_head)
{
	struct device_list *dev_tmp;
	struct inode_list *ino_tmp;
	FILE *fp;
	char line[BUFSIZ];
	char *find_mountp;
	char *find_space;
	struct stat st;

	if ( (ino_head == NULL) && (dev_head == NULL) )
		return;


	if ((fp = fopen(PROC_MOUNTS, "r")) == NULL) {
		ERROR("Cannot open %s", PROC_MOUNTS);
		return;
	}
	while (fgets(line, BUFSIZ, fp) != NULL) {
		if ((find_mountp = strchr(line, ' ')) == NULL)
			continue;
		find_mountp++;
		if ((find_space = strchr(find_mountp, ' ')) == NULL)
			continue;
		*find_space = '\0';
		if (stat(find_mountp, &st) != 0) {
			continue;
		}
		/* Scan the devices */
		for (dev_tmp = dev_head; dev_tmp != NULL;
			 dev_tmp = dev_tmp->next) {
			if (st.st_dev == dev_tmp->device)
				add_special_proc(dev_tmp->name, PTYPE_MOUNT, 0,
								 find_mountp);
		}
		for (ino_tmp = ino_head; ino_tmp != NULL;
			 ino_tmp = ino_tmp->next) {
			if (st.st_dev == ino_tmp->device
				&& st.st_ino == ino_tmp->inode)
				add_special_proc(ino_tmp->name, PTYPE_MOUNT, 0,
								 find_mountp);
		}
	}
	fclose(fp);
}

static void
scan_swaps(struct names *names_head, struct inode_list *ino_head,
		   struct device_list *dev_head)
{
	struct device_list *dev_tmp;
	struct inode_list *ino_tmp;
	FILE *fp;
	char line[BUFSIZ];
	char *find_space;
	struct stat st;

	if ( (ino_head == NULL) && (dev_head == NULL) )
		return;

	if ((fp = fopen(PROC_SWAPS, "r")) == NULL) {
		/*fprintf(stderr, "Cannot open %s\n", PROC_SWAPS); */
		return;
	}
	/* lines are filename   type */
	while (fgets(line, BUFSIZ, fp) != NULL) {
		if ((find_space = strchr(line, ' ')) == NULL)
			continue;
		*find_space = '\0';
		find_space++;
		while (*find_space == ' ') {
			find_space++;
			if (*find_space == '\0')
				continue;
		}
		if (stat(line, &st) != 0) {
			continue;
		}
		/* Scan the devices */
		for (dev_tmp = dev_head; dev_tmp != NULL;
			 dev_tmp = dev_tmp->next) {
			if (st.st_dev == dev_tmp->device)
				add_special_proc(dev_tmp->name, PTYPE_SWAP, 0,
								 line);
		}
		for (ino_tmp = ino_head; ino_tmp != NULL;
			 ino_tmp = ino_tmp->next) {
			if (st.st_dev == ino_tmp->device
				&& st.st_ino == ino_tmp->inode)
				add_special_proc(ino_tmp->name, PTYPE_SWAP, 0,
								 line);
		}
	}
	fclose(fp);
}

/*
 * Free up structures allocated in add_inode
 */
static void
free_inodes(struct inode_list **match_inodes)
{
	struct inode_list *inode_tmp, *inode_next;

	inode_tmp = *match_inodes;
	while(inode_tmp != NULL) {
		inode_next = inode_tmp->next;
		free(inode_tmp);
		inode_tmp = inode_next;
	}
	*match_inodes = NULL;
}

/*
 * Free up structures allocated in add_device
 */
static void
free_devices(struct device_list **match_devices)
{
	struct device_list *device_tmp, *device_next;

	device_tmp = *match_devices;
	while(device_tmp != NULL) {
		device_next = device_tmp->next;
		free(device_tmp);
		device_tmp = device_next;
	}
	*match_devices = NULL;
}

#define NAMESPACE_FILE 0

#define NAME_FIELD 20		/* space reserved for file name */

static const char *bus_error_message(const sd_bus_error *e, int error) {

	if (e) {
		/* Sometimes, the D-Bus server is a little bit too verbose with
		 * its error messages, so let's override them here */
		if (sd_bus_error_has_name(e, SD_BUS_ERROR_ACCESS_DENIED))
			return "Access denied";

		if (e->message)
			return e->message;
	}

	return strerror(abs(error));
}

static int get_unit_dbus_path_by_pid(
		uint32_t pid,
		char **unit) {

	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
	char *u;
	char *unit_id = NULL;
	int r;
	sd_bus *bus;

	r = sd_bus_default_system(&bus);
	if (r < 0)
		return r;

	r = sd_bus_call_method(bus,
						   "org.freedesktop.systemd1",
						   "/org/freedesktop/systemd1",
						   "org.freedesktop.systemd1.Manager",
						   "GetUnitByPID",
						   &error,
						   &reply,
						   "u",
						   pid);
	if (r < 0) {
		TRACE("Failed to request unit for PID %"PRIu32": %s", pid, bus_error_message(&error, r));
		return r;
	}

	r = sd_bus_message_read(reply, "o", &u);
	if (r < 0) {
		ERROR("Failed to get unit for PID %"PRIu32": %s", pid, bus_error_message(&error, r));
		return r;
	}

	r = sd_bus_get_property_string(
			bus,
			"org.freedesktop.systemd1",
			u,
			"org.freedesktop.systemd1.Unit",
			"Id",
			&error,
			&unit_id);
	if (r < 0) {
		ERROR("Failed to get ID: %s", bus_error_message(&error, r));
		return r;
	}

	unit_id = strdup(unit_id);
	if (!unit_id) {
		ERROR("diskpivot OOM");
		return -ENOMEM;
	}

	*unit = unit_id;
	return 0;
}

static int restart_service(char *unit_id) {
	_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	char *job = NULL;
	int r;

	sd_bus *bus;

	r = sd_bus_default_system(&bus);
	if (r < 0)
		return r;

	r = sd_bus_call_method(bus,
						   "org.freedesktop.systemd1",
						   "/org/freedesktop/systemd1",
						   "org.freedesktop.systemd1.Manager",
						   "RestartUnit",
						   &error,
						   &reply,
						   "ss",
						   unit_id,
						   "replace");

	if (r < 0) {
		ERROR("Failed to issue method call: %s", bus_error_message(&error, r));
		return r;
	}

	r = sd_bus_message_read(reply, "o", &job);
	if (r < 0) {
		ERROR("Failed to read reply for restarting service %s: %s", unit_id, bus_error_message(&error, r));
		return r;
	}
	TRACE("Got job response for service %s: %s", unit_id, job);

	return 0;
}

/*
 * returns 0 if match, 1 if no match
 */
static int
print_matches(struct names *names_head)
{
	struct names *nptr;
	struct procs *pptr;
	char head = 0;
	char first = 1;
	int len = 0;
	struct passwd *pwent = NULL;
	int have_match = 0;
	int have_kill = 0;
	int name_has_procs = 0;
	int r;
	bool skip;
	pid_t my_pid;
	char *my_unit = NULL;

	my_pid = getpid();

	r = get_unit_dbus_path_by_pid(my_pid, &my_unit);
	if (r < 0)
		WARN("Failed to get my unit for PID: %d", my_pid);

	for (nptr = names_head; nptr != NULL; nptr = nptr->next) {
		if (name_has_procs == 1) {
			if (head == 0) {
				//INFO("%*s USER        PID ACCESS COMMAND",
						//NAME_FIELD, "");
				head = 1;
			}

			//INFO("%s:", nptr->filename);
			len = strlen(nptr->filename) + 1;
		}

		first = 1;
		for (pptr = nptr->matched_procs; pptr != NULL;
			 pptr = pptr->next) {
			/* Suppress any special "processes" */
			//if (!(opts & OPT_VERBOSE)
				//&& (pptr->proc_type != PTYPE_NORMAL))
				//continue;

			have_match = 1;
			if (pwent == NULL || pwent->pw_uid != pptr->uid)
				pwent = getpwuid(pptr->uid);
			if (len > NAME_FIELD) {
				//putc('\n', stderr);
				len = 0;
			}
			//while (len++ < NAME_FIELD)
				//putc(' ', stderr);
//			if (pwent == NULL)
//				INFO(" %-8s ", "(unknown)");
//			else
//				INFO(" %-8s ", pwent->pw_name);

			if (pptr->proc_type == PTYPE_NORMAL) {
				//INFO(" %5d", pptr->pid);
				if (pptr->pid == my_pid)
					skip = true;
				else
					skip = false;
				char *unit = NULL;
				r = get_unit_dbus_path_by_pid(pptr->pid, &unit);
				//WARN(" %5d", pptr->pid);
				if (r < 0) {
					WARN("Failed to get unit for PID: %d", pptr->pid);
				} else {
					if (strcmp(my_unit,unit) == 0)
						skip = true;
					if (!skip) {
						TRACE("Restarting unit: %s", unit);
						r = restart_service(unit);
						if (r < 0)
							ERROR("Failed to restart service: %s", unit);
						else
							INFO("Unit restarted: %s", unit);
					} else {
						TRACE("Skipping restart for unit: %s", unit);
					}

				}
			}
			//else
				//INFO("kernel");
			//fflush(stdout);
//			switch (pptr->proc_type) {
//				case PTYPE_KNFSD:
//					INFO(" knfsd ");
//					break;
//				case PTYPE_MOUNT:
//					INFO(" mount ");
//					break;
//				case PTYPE_SWAP:
//					INFO(" swap  ");
//					break;
//				default:
//					INFO(" %c%c%c%c%c ",
//							pptr->access &
//							ACCESS_FILE
//							? (pptr->access &
//							   ACCESS_FILEWR ? 'F' :
//							   'f') : '.',
//							pptr->
//									access & ACCESS_ROOT ?
//							'r' : '.',
//							pptr->
//									access & ACCESS_CWD ?
//							'c' : '.',
//							pptr->
//									access & ACCESS_EXE ?
//							'e' : '.',
//							(pptr->
//									access & ACCESS_MMAP)
//							&& !(pptr->
//									access &
//								 ACCESS_EXE) ? 'm' :
//							'.');
//			}	/* switch */
//			if (pptr->command == NULL)
//				INFO("???");
//			else
//				INFO("%s", pptr->command);
			len = 0;
			first = 0;
		}
		/* put a newline if showing all files and no procs */
		//if (nptr->matched_procs == NULL)
			//putc('\n', stderr);

	}			/* next name */
	return (have_match == 1 ? 0 : 1);
}

static void read_proc_mounts(struct mount_list **mnt_list)
{
	FILE *fp;
	char line[BUFSIZ];
	char *find_mountp;
	char *find_space;
	struct mount_list *mnt_tmp;

	if ((fp = fopen(PROC_MOUNTS, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s\n", PROC_MOUNTS);
		return;
	}
	while (fgets(line, BUFSIZ, fp) != NULL) {
		if ((find_mountp = strchr(line, ' ')) == NULL)
			continue;
		find_mountp++;
		if ((find_space = strchr(find_mountp, ' ')) == NULL)
			continue;
		*find_space = '\0';
		if ((mnt_tmp = malloc(sizeof(struct mount_list))) == NULL)
			continue;
		if ((mnt_tmp->mountpoint = strdup(find_mountp)) == NULL) {
			free(mnt_tmp);
			continue;
		}
		mnt_tmp->next = *mnt_list;
		*mnt_list = mnt_tmp;
	}
	fclose(fp);
}

static int is_mountpoint(struct mount_list **mnt_list, char *arg)
{
	char *p;
	struct mount_list *mnt_tmp;

	if (*arg == '\0')
		return 0;
	/* Remove trailing slashes. */
	for (p = arg; *p != '\0'; p++) ;
	while (*(--p) == '/' && p > arg)
		*p = '\0';

	for (mnt_tmp = *mnt_list; mnt_tmp != NULL; mnt_tmp = mnt_tmp->next)
		if (!strcmp(mnt_tmp->mountpoint, arg))
			return 1;
	return 0;
}


static void check_mountpoints(struct mount_list **mnt_list, struct names **head, struct names **tail)
{
	struct names *this, *last;

	last = NULL;
	for(this = *head; this != NULL; this = this->next) {
		if (this->name_space == NAMESPACE_FILE &&
			!is_mountpoint(mnt_list, this->filename)) {
			ERROR("Specified filename %s is not a mountpoint.",
					this->filename);
			/* Remove from list */
			if (last)
				last->next = this->next;
			if (*head == this)
				*head = this->next;
			if (*tail == this)
				*tail = last;
		} else {
			last = this;
		}
	}
}

static void
free_proc_mounts(struct mount_list *mnt_list)
{
	struct mount_list *mnt_tmp, *mnt_next;

	mnt_tmp = mnt_list;
	while(mnt_tmp != NULL) {
		mnt_next = mnt_tmp->next;
		free(mnt_tmp->mountpoint);
		free(mnt_tmp);
		mnt_tmp = mnt_next;
	}
}

/* MAXSYMLINKS is a BSDism.  If it doesn't exist, fall back to SYMLINK_MAX,
   which is the POSIX name. */
#ifndef MAXSYMLINKS
#define MAXSYMLINKS 255
#endif


/*
 * Somehow the realpath(3) glibc function call, nevertheless
 * it avoids lstat(2) system calls.
 */
static char real[PATH_MAX + 1];
static char *expandpath(const char *path)
{
	char tmpbuf[PATH_MAX + 1];
	const char *start, *end;
	char *curr, *dest;
	int deep = MAXSYMLINKS;

	if (!path || *path == '\0')
		return (char *)0;

	curr = &real[0];

	if (*path != '/') {
		if (!getcwd(curr, PATH_MAX))
			return (char *)0;
#ifdef HAVE_RAWMEMCHR
		dest = rawmemchr(curr, '\0');
#else
		dest = strchr(curr, '\0');
#endif
	} else {
		*curr = '/';
		dest = curr + 1;
	}

	for (start = end = path; *start; start = end) {

		while (*start == '/')
			++start;

		for (end = start; *end && *end != '/'; ++end) ;

		if (end - start == 0)
			break;
		else if (end - start == 1 && start[0] == '.') {
			;
		} else if (end - start == 2 && start[0] == '.'
				   && start[1] == '.') {
			if (dest > curr + 1)
				while ((--dest)[-1] != '/') ;
		} else {
			char lnkbuf[PATH_MAX + 1];
			size_t len;
			ssize_t n;

			if (dest[-1] != '/')
				*dest++ = '/';

			if (dest + (end - start) > curr + PATH_MAX) {
				errno = ENAMETOOLONG;
				return (char *)0;
			}

			dest = mempcpy(dest, start, end - start);
			*dest = '\0';

			if (deep-- < 0) {
				errno = ELOOP;
				return (char *)0;
			}

			errno = 0;
			if ((n = readlink(curr, lnkbuf, PATH_MAX)) < 0) {
				deep = MAXSYMLINKS;
				if (errno == EINVAL)
					continue;	/* Not a symlink */
				return (char *)0;
			}
			lnkbuf[n] = '\0';	/* Don't be fooled by readlink(2) */

			len = strlen(end);
			if ((n + len) > PATH_MAX) {
				errno = ENAMETOOLONG;
				return (char *)0;
			}

			memmove(&tmpbuf[n], end, len + 1);
			path = end = memcpy(tmpbuf, lnkbuf, n);

			if (lnkbuf[0] == '/')
				dest = curr + 1;
			else if (dest > curr + 1)
				while ((--dest)[-1] != '/') ;

		}
	}

	if (dest > curr + 1 && dest[-1] == '/')
		--dest;
	*dest = '\0';

	return curr;
}

static void
add_inode(struct inode_list **ino_list, struct names *this_name,
		  dev_t device, ino_t inode)
{
	struct inode_list *ino_tmp, *ino_head;

	if ((ino_tmp =
				 (struct inode_list *)malloc(sizeof(struct inode_list))) == NULL)
		return;
	ino_head = *ino_list;
	ino_tmp->name = this_name;
	ino_tmp->device = device;
	ino_tmp->inode = inode;
	ino_tmp->next = ino_head;
	*ino_list = ino_tmp;
}



static int parse_file(struct names *this_name, struct inode_list **ino_list)
{
	char *new = expandpath(this_name->filename);
	if (new) {
		if (this_name->filename)
			free(this_name->filename);
		this_name->filename = strdup(new);
	}
	if (stat(this_name->filename, &(this_name->st)) != 0) {
		if (errno == ENOENT)
			ERROR("Specified filename %s does not exist.",
					this_name->filename);
		else
			ERROR("Cannot stat %s: %s",
					this_name->filename, strerror(errno));
		return -1;
	}
#ifdef DEBUG
	printf("adding file %s %lX %lX\n", this_name->filename,
	       (unsigned long)this_name->st.st_dev,
	       (unsigned long)this_name->st.st_ino);
#endif				/* DEBUG */
	add_inode(ino_list, this_name, this_name->st.st_dev,
			  this_name->st.st_ino);
	return 0;
}


static int scan_mount(const char *path)
{
	struct names *this_name = NULL;
	static struct unixsocket_list *unixsockets = NULL;
	static struct names *names_head = NULL, *names_tail = NULL;
	static struct device_list *match_devices = NULL;
	static struct inode_list *match_inodes = NULL;
	dev_t netdev;
	int ret = 0;

	netdev = find_net_dev();

	this_name = malloc(sizeof(struct names));
	this_name->filename = strdup(path);
	this_name->next = NULL;
	this_name->name_space = NAMESPACE_FILE;
	this_name->matched_procs = NULL;

	if (parse_file(this_name, &match_inodes) == 0) {
		parse_mounts(this_name, &match_devices);
	}

	if (names_head == NULL)
		names_head = this_name;
	if (names_tail != NULL)
		names_tail->next = this_name;
	names_tail = this_name;

	if (names_head == NULL)
		ERROR("No process specification given");

	struct mount_list *mounts = NULL;
	read_proc_mounts(&mounts);
	check_mountpoints(&mounts, &names_head, &names_tail);
	free_proc_mounts(mounts);

	debug_match_lists(names_head, match_inodes, match_devices);

	scan_procs(names_head, match_inodes, match_devices, unixsockets, netdev);
	scan_knfsd(names_head, match_inodes, match_devices);
	scan_mounts(names_head, match_inodes, match_devices);
	scan_swaps(names_head, match_inodes, match_devices);

	free_inodes(&match_inodes);
	free_devices(&match_devices);

	print_matches(names_head);

	return ret;
}

/*
 * Checks if file system fstype already exists on device.
 * return 0 if not exists, 1 if exists, negative values on failure
 */
static int fs_exists(char *device)
{
	char buf[10];
	const char *value = buf;
	size_t len;
	blkid_probe pr;
	int ret = 0;

	pr = blkid_new_probe_from_filename(device);

	if (!pr) {
		ERROR("%s: failed to create libblkid probe",
		      device);
		return -EFAULT;
	}

	while (blkid_do_probe(pr) == 0) {
		if (blkid_probe_lookup_value(pr, "TYPE", &value, &len)) {
			ERROR("blkid_probe_lookup_value failed");
			ret = -EFAULT;
			break;
		}
	}
	blkid_free_probe(pr);

	return ret;
}

static int diskpivot(struct img_type *img,
		      void __attribute__ ((__unused__)) *data)
{
	int ret = 0;

	if (!strlen(img->device)) {
		ERROR("diskpivot handler requires setting \"device\" attribute");
		return -EINVAL;
	}

	/* Check if file system exists */
	//ret = fs_exists(img->device);

	//if (ret < 0)
		//return ret;

	ERROR("scan for pid's start");
	scan_mount(img->device);
	ERROR("scan for pid's end");

	return ret;
}

__attribute__((constructor))
void diskpivot_handler(void)
{
	register_handler("diskpivot", diskpivot,
			 PARTITION_HANDLER | NO_DATA_HANDLER, NULL);
}
