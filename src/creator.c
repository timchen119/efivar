/*
 * libefiboot - library for the manipulation of EFI boot variables
 * Copyright 2012-2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include "fix_coverity.h"

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <mntent.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <syslog.h>

#include "efiboot.h"

static int NONNULL(1, 2, 3)
find_file(const char * const filepath, char **devicep, char **relpathp)
{
	struct stat fsb = { 0, };
	int rc;
	int ret = -1;
	FILE *mounts = NULL;
	char linkbuf[PATH_MAX+1] = "";
	ssize_t linklen = 0;

	linklen = strlen(filepath);
	if (linklen > PATH_MAX) {
		errno = ENAMETOOLONG;
		syslog(LOG_CRIT,"efivar, creator.c: filepath length exceeds PATH_MAX");
		return -1;
	}
	strcpy(linkbuf, filepath);

	do {
		rc = stat(linkbuf, &fsb);
		if (rc < 0)
			return rc;

		if (S_ISLNK(fsb.st_mode)) {
			char tmp[PATH_MAX+1] = "";
			ssize_t l;

			l = readlink(linkbuf, tmp, PATH_MAX);
			if (l < 0) {
				syslog(LOG_CRIT,"efivar, creator.c: readlink failed");
				return -1;
			}
			tmp[l] = '\0';
			linklen = l;
			strcpy(linkbuf, tmp);
		} else {
			break;
		}
	} while (1);

	mounts = fopen("/proc/self/mounts", "r");
	if (mounts == NULL) {
		syslog(LOG_CRIT,"efivar, creator.c: couldn not open /proc/self/mounts");
		return -1;
	}

	struct mntent *me;
	while (1) {
		struct stat dsb = { 0, };

		errno = 0;
		me = getmntent(mounts);
		if (!me) {
			if (feof(mounts)) {
				errno = ENOENT;
				syslog(LOG_CRIT,"efivar, creator.c: could not find mountpoint");
			}
			goto err;
		}

		if (me->mnt_fsname[0] != '/')
			continue;

		rc = stat(me->mnt_fsname, &dsb);
		if (rc < 0) {
			if (errno == ENOENT)
				continue;
			syslog(LOG_CRIT,"efivar, creator.c: could not stat mountpoint");
			goto err;
		}

		if (!S_ISBLK(dsb.st_mode))
			continue;

		if (dsb.st_rdev == fsb.st_dev) {
			ssize_t mntlen = strlen(me->mnt_dir);
			if (mntlen >= linklen)
				continue;
			if (strncmp(linkbuf, me->mnt_dir, mntlen))
				continue;
			*devicep = strdup(me->mnt_fsname);
			if (!*devicep) {
				errno = ENOMEM;
				syslog(LOG_CRIT,"efivar, creator.c: strdup failed");
				goto err;
			}
			*relpathp = strdup(linkbuf + mntlen);
			if (!*relpathp) {
				free(*devicep);
				*devicep = NULL;
				errno = ENOMEM;
				syslog(LOG_CRIT,"efivar, creator.c: strdup failed");
				goto err;
			}
			ret = 0;
			break;
		}
	}
err:
	if (mounts)
		endmntent(mounts);
	return ret;
}

static int
open_disk(struct device *dev, int flags)
{
	char *diskpath = NULL;
	int rc;

	rc = asprintfa(&diskpath, "/dev/%s", dev->disk_name);
	if (rc < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not allocate buffer");
		return -1;
	}

	rc = open(diskpath, flags);
	if (rc < 0)
		syslog(LOG_CRIT,"efivar, creator.c: could not open disk");

	return rc;
}

static char *
tilt_slashes(char *s)
{
	char *p;
	for (p = s; *p; p++)
		if (*p == '/')
			*p = '\\';
	return s;
}

ssize_t
efi_va_generate_file_device_path_from_esp(uint8_t *buf, ssize_t size,
				       const char *devpath, int partition,
				       const char *relpath,
				       uint32_t options, va_list ap)
{
	ssize_t ret = -1, off = 0, sz;
	struct device *dev = NULL;
	int fd = -1;
	int saved_errno;

	syslog(LOG_CRIT, "partition:%d", partition);

	if (buf && size)
		memset(buf, '\0', size);

	syslog(LOG_CRIT, "devpath:%s", devpath);
	syslog(LOG_CRIT, "relpath:%s", relpath);
	fd = open(devpath, O_RDONLY);
	if (fd < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not open device for ESP");
	} else {
		dev = device_get(fd, partition);
		if (dev == NULL) {
			syslog(LOG_CRIT,"efivar, creator.c: could not get ESP disk info");
			goto err;
		}
		if (partition < 0) {
			int disk_fd;

			syslog(LOG_CRIT, "partition: %d", partition);
			disk_fd = open_disk(dev,
					    (options & EFIBOOT_OPTIONS_WRITE_SIGNATURE)
					     ? O_RDWR : O_RDONLY);
			syslog(LOG_CRIT, "open_disk 1");
			if (disk_fd < 0) {
				syslog(LOG_CRIT,"efivar, creator.c: could not open disk");
				goto err;
			}

			if (is_partitioned(disk_fd))
				partition = 1;
			else
				partition = 0;
			syslog(LOG_CRIT, "is_partitioned(): partition -> %d", partition);

			close(disk_fd);
		}

		set_part(dev, partition);

		if (partition == 0) {
			options |= EFIBOOT_ABBREV_NONE;
			options &= ~(EFIBOOT_ABBREV_HD|
				     EFIBOOT_ABBREV_FILE|
				     EFIBOOT_ABBREV_EDD10);
		}
	}

	if (options & EFIBOOT_ABBREV_NONE)
		syslog(LOG_CRIT, "EFIBOOT_ABBREV_NONE");
	if (options & EFIBOOT_ABBREV_HD)
		syslog(LOG_CRIT, "EFIBOOT_ABBREV_HD");
	if (options & EFIBOOT_ABBREV_FILE)
		syslog(LOG_CRIT, "EFIBOOT_ABBREV_FILE");
	if (options & EFIBOOT_ABBREV_EDD10)
		syslog(LOG_CRIT, "EFIBOOT_ABBREV_EDD10");

	if (options & EFIBOOT_ABBREV_EDD10) {
		va_list aq;
		va_copy(aq, ap);

		dev->edd10_devicenum = va_arg(aq, uint32_t);

		va_end(aq);
	}

        if (!(options & (EFIBOOT_ABBREV_FILE|EFIBOOT_ABBREV_HD)) &&
            (dev->flags & DEV_ABBREV_ONLY)) {
                errno = EINVAL;
                syslog(LOG_CRIT,"efivar, creator.c: Device must use File() or HD() device path");
                goto err;
        }

	if ((options & EFIBOOT_ABBREV_EDD10)
			&& (!(options & EFIBOOT_ABBREV_FILE)
			    && !(options & EFIBOOT_ABBREV_HD))) {
		syslog(LOG_CRIT,"efivar, creator.c: test1");
		sz = efidp_make_edd10(buf, size, dev->edd10_devicenum);
		if (sz < 0) {
			syslog(LOG_CRIT,"efivar, creator.c: could not make EDD 1.0 device path");
			goto err;
		}
		off = sz;
	} else if (!(options & EFIBOOT_ABBREV_FILE)
		   && !(options & EFIBOOT_ABBREV_HD)) {

		/*
		 * We're probably on a modern kernel, so just parse the
		 * symlink from /sys/dev/block/$major:$minor and get it
		 * from there.
		 */
		syslog(LOG_CRIT,"efivar, creator.c: test2");
		sz = make_blockdev_path(buf, size, dev);
		if (sz < 0) {
			syslog(LOG_CRIT,"efivar, creator.c: could not create device path");
			goto err;
		}
		off += sz;
	}

	if ((!(options & EFIBOOT_ABBREV_FILE) && dev && dev->part_name) ||
	    ((options & EFIBOOT_ABBREV_HD) && dev && ! dev->part_name)) {
		int disk_fd;
		int saved_errno;
		
		syslog(LOG_CRIT, "test3");

		disk_fd = open_disk(dev,
				    (options & EFIBOOT_OPTIONS_WRITE_SIGNATURE)
				     ? O_RDWR : O_RDONLY);
		syslog(LOG_CRIT, "open_disk 2");
	
		if (disk_fd < 0) {
			syslog(LOG_CRIT,"efivar, creator.c: could not open disk");
			goto err;
		}

		sz = make_hd_dn(buf+off, size?size-off:0,
                                disk_fd, dev->part, options);
		saved_errno = errno;
		close(disk_fd);
		errno = saved_errno;
		if (sz < 0) {
			syslog(LOG_CRIT,"efivar, creator.c: could not make HD() DP node");
			goto err;
		}
		off += sz;
	}
	
	if (fd < 0 && !dev && (options & EFIBOOT_ABBREV_HD)) {
		syslog(LOG_CRIT, "test4 + dependency udev %s %d", devpath, partition);
		
		sz = make_hd_dn_udev(buf+off, size?size-off:0, devpath, partition, options);

		if (sz < 0) {
			syslog(LOG_CRIT,"efivar, creator.c: could not make HD() DP node from udev");
			goto err;
		}		
		off += sz;
	}
	
	syslog(LOG_CRIT, "buf:%s,relpath:%s", buf,relpath);

	char *filepath = strdupa(relpath);
	tilt_slashes(filepath);
	sz = efidp_make_file(buf+off, size?size-off:0, filepath);
	if (sz < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not make File() DP node");
		goto err;
	}
	off += sz;

	sz = efidp_make_end_entire(buf+off, size?size-off:0);
	if (sz < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not make EndEntire DP node");
		goto err;
	}
	off += sz;
	ret = off;
err:
	saved_errno = errno;
	if (dev)
		device_free(dev);
	if (fd >= 0)
		close(fd);
	errno = saved_errno;
	syslog(LOG_CRIT, "= %zd", ret);
	return ret;
}

ssize_t NONNULL(3, 5) PUBLIC
efi_generate_file_device_path_from_esp(uint8_t *buf, ssize_t size,
				       const char *devpath, int partition,
				       const char *relpath,
				       uint32_t options, ...)
{
	ssize_t ret;
	int saved_errno;
	va_list ap;

	va_start(ap, options);
	ret = efi_va_generate_file_device_path_from_esp(buf, size, devpath,
							partition, relpath,
							options, ap);
	saved_errno = errno;
	va_end(ap);
	errno = saved_errno;
	if (ret < 0)
		syslog(LOG_CRIT,"efivar, creator.c: could not generate File DP from ESP");
	return ret;
}

ssize_t NONNULL(3) PUBLIC
efi_generate_file_device_path(uint8_t *buf, ssize_t size,
			      const char * const filepath,
			      uint32_t options, ...)
{
	int rc;
	ssize_t ret = -1;
	char *child_devpath = NULL;
	char *parent_devpath = NULL;
	char *relpath = NULL;
	va_list ap;
	int saved_errno;
	
	syslog(LOG_CRIT, "rerate_file_device_path 1");
	syslog(LOG_CRIT, "1 filepath:%s,child_dev_path:%s,parent_devpath:%s,relpath:%s", filepath,child_devpath,parent_devpath,relpath);

	rc = find_file(filepath, &child_devpath, &relpath);
	if (rc < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not canonicalize fs path");
		goto err;
	}
	
	syslog(LOG_CRIT, "2 filepath:%s,child_dev_path:%s,parent_devpath:%s,relpath:%s", filepath,child_devpath,parent_devpath,relpath);
	
	syslog(LOG_CRIT, "rerate_file_device_path 2");


	rc = find_parent_devpath(child_devpath, &parent_devpath);
	if (rc < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not find parent device for file");
		goto err;
	}
	
	syslog(LOG_CRIT, "3 filepath:%s,child_dev_path:%s,parent_devpath:%s,relpath:%s", filepath,child_devpath,parent_devpath,relpath);
	
	syslog(LOG_CRIT, "rerate_file_device_path 3");

	va_start(ap, options);

	if (!strcmp(parent_devpath, "/dev/block")) {
		ret = efi_va_generate_file_device_path_from_esp(buf, size,
							child_devpath, rc,
							relpath, options, ap);
	syslog(LOG_CRIT, "rerate_file_device_path 4");
	}
	else if (!strncmp(relpath, "/EFI/ubuntu/",12)){
		ret = efi_va_generate_file_device_path_from_esp(buf, size,
							child_devpath, rc,
							relpath, options, ap);
		syslog(LOG_CRIT, "rerate_file_device_path /boot/efi 4.5");
	}
	else {
		ret = efi_va_generate_file_device_path_from_esp(buf, size,
							parent_devpath, rc,
							relpath, options, ap);
	syslog(LOG_CRIT, "rerate_file_device_path 5");
	}
	saved_errno = errno;
	va_end(ap);
	errno = saved_errno;
	if (ret < 0)
	{
		syslog(LOG_CRIT, "rerate_file_device_path 6");
		syslog(LOG_CRIT,"efivar, creator.c: could not generate File DP from ESP");
	}
	syslog(LOG_CRIT, "4 filepath:%s,child_dev_path:%s,parent_devpath:%s,relpath:%s", filepath,child_devpath,parent_devpath,relpath);	
err:
	syslog(LOG_CRIT, "rerate_file_device_path 7");
	saved_errno = errno;
	if (child_devpath)
		free(child_devpath);
	if (parent_devpath)
		free(parent_devpath);
	if (relpath)
		free(relpath);
	errno = saved_errno;
	return ret;
}

static ssize_t NONNULL(3, 4, 5, 6)
make_ipv4_path(uint8_t *buf, ssize_t size,
	       const char * const local_addr UNUSED,
	       const char * const remote_addr UNUSED,
	       const char * const gateway_addr UNUSED,
	       const char * const netmask UNUSED,
	       uint16_t local_port UNUSED,
	       uint16_t remote_port UNUSED,
	       uint16_t protocol UNUSED,
	       uint8_t addr_origin UNUSED)
{
	ssize_t ret;

#if 0
	if (local_addr == NULL || remote_addr == NULL ||
	    gateway_addr == NULL || netmask == NULL) {
		errno = EINVAL;
		return -1;
	}
#endif
	ret = efidp_make_ipv4(buf, size, 0, 0, 0, 0, 0, 0, 0, 0);
	if (ret < 0)
		syslog(LOG_CRIT,"efivar, creator.c: could not make ipv4 DP node");
	return ret;
}

ssize_t NONNULL(3, 4, 5, 6, 7) PUBLIC
efi_generate_ipv4_device_path(uint8_t *buf, ssize_t size,
			      const char * const ifname,
			      const char * const local_addr,
			      const char * const remote_addr,
			      const char * const gateway_addr,
			      const char * const netmask,
			      uint16_t local_port,
			      uint16_t remote_port,
			      uint16_t protocol,
			      uint8_t addr_origin)
{
	ssize_t off = 0;
	ssize_t sz;

	sz = make_mac_path(buf, size, ifname);
	if (sz < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not make MAC DP node");
		return -1;
	}
	off += sz;

	sz = make_ipv4_path(buf+off, size?size-off:0, local_addr, remote_addr,
			    gateway_addr, netmask, local_port, remote_port,
			    protocol, addr_origin);
	if (sz < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not make IPV4 DP node");
		return -1;
	}
	off += sz;

	sz = efidp_make_end_entire(buf+off, size?size-off:0);
	if (sz < 0) {
		syslog(LOG_CRIT,"efivar, creator.c: could not make EndEntire DP node");
		return -1;
	}
	off += sz;

	return off;
}
