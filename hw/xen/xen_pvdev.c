/*
 * Xen para-virtualization device
 *
 *  Copyright (c) 2015 Intel Corporation
 *  Authors:
 *    Quan Xu <quan.xu@intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/signal.h>

#include "hw/hw.h"
#include "sysemu/char.h"
#include "qemu/log.h"
#include "hw/xen/xen_backend.h"

#include <xen/grant_table.h>

static QTAILQ_HEAD(XenDeviceHead, XenDevice) xendevs =
           QTAILQ_HEAD_INITIALIZER(xendevs);
static int debug;

/* public */
XenXC xen_xc = XC_HANDLER_INITIAL_VALUE;
struct xs_handle *xenstore;

/*
 * find Xen device
 */
struct XenDevice *xen_find_xendev(const char *type, int dom, int dev)
{
    struct XenDevice *xendev;

    QTAILQ_FOREACH(xendev, &xendevs, next) {
        if (xendev->dom != dom) {
            continue;
        }
        if (xendev->dev != dev) {
            continue;
        }
        if (strcmp(xendev->type, type) != 0) {
            continue;
        }
        return xendev;
    }
    return NULL;
}

/*
 * get xen backend device, allocate a new one if it doesn't exist.
 */
struct XenDevice *xen_be_get_xendev(const char *type, int dom, int dev,
                                    struct XenDevOps *ops)
{
    struct XenDevice *xendev;

    xendev = xen_find_xendev(type, dom, dev);
    if (xendev) {
        return xendev;
    }

    /* init new xendev */
    xendev = g_malloc0(ops->size);
    xendev->type  = type;
    xendev->dom   = dom;
    xendev->dev   = dev;
    xendev->ops   = ops;

    snprintf(xendev->be, sizeof(xendev->be), "backend/%s/%d/%d",
             xendev->type, xendev->dom, xendev->dev);
    snprintf(xendev->name, sizeof(xendev->name), "%s-%d",
             xendev->type, xendev->dev);

    xendev->debug      = debug;
    xendev->local_port = -1;

    xendev->evtchndev = xen_xc_evtchn_open(NULL, 0);
    if (xendev->evtchndev == XC_HANDLER_INITIAL_VALUE) {
        xen_be_printf(NULL, 0, "can't open evtchn device\n");
        g_free(xendev);
        return NULL;
    }
    fcntl(xc_evtchn_fd(xendev->evtchndev), F_SETFD, FD_CLOEXEC);

    if (ops->flags & DEVOPS_FLAG_NEED_GNTDEV) {
        xendev->gnttabdev = xen_xc_gnttab_open(NULL, 0);
        if (xendev->gnttabdev == XC_HANDLER_INITIAL_VALUE) {
            xen_be_printf(NULL, 0, "can't open gnttab device\n");
            xc_evtchn_close(xendev->evtchndev);
            g_free(xendev);
            return NULL;
        }
    } else {
        xendev->gnttabdev = XC_HANDLER_INITIAL_VALUE;
    }

    QTAILQ_INSERT_TAIL(&xendevs, xendev, next);

    if (xendev->ops->alloc) {
        xendev->ops->alloc(xendev);
    }

    return xendev;
}

/*
 * get xen fe device, allocate a new one if it doesn't exist.
 */
struct XenDevice *xen_fe_get_xendev(const char *type, int dom, int dev,
                                    char *backend, struct XenDevOps *ops)
{
    struct XenDevice *xendev;

    xendev = xen_find_xendev(type, dom, dev);
    if (xendev) {
        return xendev;
    }

    /* init new xendev */
    xendev = g_malloc0(ops->size);
    xendev->type  = type;
    xendev->dom   = dom;
    xendev->dev   = dev;
    xendev->ops   = ops;

    /*return if the ops->flags is not DEVOPS_FLAG_FE*/
    if (!(ops->flags & DEVOPS_FLAG_FE)) {
        return NULL;
    }

    snprintf(xendev->be, sizeof(xendev->be), "%s", backend);
    snprintf(xendev->name, sizeof(xendev->name), "%s-%d",
             xendev->type, xendev->dev);

    xendev->debug = debug;
    xendev->local_port = -1;

    xendev->evtchndev = xen_xc_evtchn_open(NULL, 0);
    if (xendev->evtchndev == XC_HANDLER_INITIAL_VALUE) {
        xen_be_printf(NULL, 0, "can't open evtchn device\n");
        g_free(xendev);
        return NULL;
    }
    fcntl(xc_evtchn_fd(xendev->evtchndev), F_SETFD, FD_CLOEXEC);

    if (ops->flags & DEVOPS_FLAG_NEED_GNTDEV) {
        xendev->gnttabdev = xen_xc_gnttab_open(NULL, 0);
        if (xendev->gnttabdev == XC_HANDLER_INITIAL_VALUE) {
            xen_be_printf(NULL, 0, "can't open gnttab device\n");
            xc_evtchn_close(xendev->evtchndev);
            g_free(xendev);
            return NULL;
        }
    } else {
        xendev->gnttabdev = XC_HANDLER_INITIAL_VALUE;
    }

    QTAILQ_INSERT_TAIL(&xendevs, xendev, next);

    if (xendev->ops->alloc) {
        xendev->ops->alloc(xendev);
    }

    return xendev;
}

/*
 * release xen device
 */

struct XenDevice *xen_del_xendev(int dom, int dev)
{
    struct XenDevice *xendev, *xnext;

    /*
     * This is pretty much like QTAILQ_FOREACH(xendev, &xendevs, next) but
     * we save the next pointer in xnext because we might free xendev.
     */
    xnext = xendevs.tqh_first;
    while (xnext) {
        xendev = xnext;
        xnext = xendev->next.tqe_next;

        if (xendev->dom != dom) {
            continue;
        }
        if (xendev->dev != dev && dev != -1) {
            continue;
        }

        if (xendev->ops->free) {
            xendev->ops->free(xendev);
        }

        if (xendev->fe) {
            char token[XEN_BUFSIZE];
            snprintf(token, sizeof(token), "fe:%p", xendev);
            xs_unwatch(xenstore, xendev->fe, token);
            g_free(xendev->fe);
        }

        if (xendev->evtchndev != XC_HANDLER_INITIAL_VALUE) {
            xc_evtchn_close(xendev->evtchndev);
        }
        if (xendev->gnttabdev != XC_HANDLER_INITIAL_VALUE) {
            xc_gnttab_close(xendev->gnttabdev);
        }

        QTAILQ_REMOVE(&xendevs, xendev, next);
        g_free(xendev);
    }
    return NULL;
}

/* ------------------------------------------------------------- */

int xenstore_write_str(const char *base, const char *node, const char *val)
{
    char abspath[XEN_BUFSIZE];

    snprintf(abspath, sizeof(abspath), "%s/%s", base, node);
    if (!xs_write(xenstore, 0, abspath, val, strlen(val))) {
        return -1;
    }
    return 0;
}

char *xenstore_read_str(const char *base, const char *node)
{
    char abspath[XEN_BUFSIZE];
    unsigned int len;
    char *str, *ret = NULL;

    snprintf(abspath, sizeof(abspath), "%s/%s", base, node);
    str = xs_read(xenstore, 0, abspath, &len);
    if (str != NULL) {
        /* move to qemu-allocated memory to make sure
         * callers can savely g_free() stuff. */
        ret = g_strdup(str);
        free(str);
    }
    return ret;
}

int xenstore_write_int(const char *base, const char *node, int ival)
{
    char val[12];

    snprintf(val, sizeof(val), "%d", ival);
    return xenstore_write_str(base, node, val);
}

int xenstore_write_int64(const char *base, const char *node, int64_t ival)
{
    char val[21];

    snprintf(val, sizeof(val), "%"PRId64, ival);
    return xenstore_write_str(base, node, val);
}

int xenstore_read_int(const char *base, const char *node, int *ival)
{
    char *val;
    int rc = -1;

    val = xenstore_read_str(base, node);
    if (val && 1 == sscanf(val, "%d", ival)) {
        rc = 0;
    }
    g_free(val);
    return rc;
}

int xenstore_read_uint64(const char *base, const char *node, uint64_t *uval)
{
    char *val;
    int rc = -1;

    val = xenstore_read_str(base, node);
    if (val && 1 == sscanf(val, "%"SCNu64, uval)) {
        rc = 0;
    }
    g_free(val);
    return rc;
}

char *xenstore_get_domain_name(uint32_t domid)
{
    char *dom_path, *str, *ret = NULL;;

    dom_path = xs_get_domain_path(xenstore, domid);
    str = xenstore_read_str(dom_path, "name");
    free(dom_path);
    if (str != NULL) {
        ret = g_strdup(str);
        free(str);
    }

    return ret;
}

/*
 * Sync internal data structures on xenstore updates.
 * Node specifies the changed field.  node = NULL means
 * update all fields (used for initialization).
 */
void xen_be_backend_changed(struct XenDevice *xendev, const char *node)
{
    if (node == NULL  ||  strcmp(node, "online") == 0) {
        if (xenstore_read_be_int(xendev, "online", &xendev->online) == -1) {
            xendev->online = 0;
        }
    }

    if (node) {
        xen_be_printf(xendev, 2, "backend update: %s\n", node);
        if (xendev->ops->backend_changed) {
            xendev->ops->backend_changed(xendev, node);
        }
    }
}

void xen_be_frontend_changed(struct XenDevice *xendev, const char *node)
{
    int fe_state;

    if (node == NULL  ||  strcmp(node, "state") == 0) {
        if (xenstore_read_fe_int(xendev, "state", &fe_state) == -1) {
            fe_state = XenbusStateUnknown;
        }
        if (xendev->fe_state != fe_state) {
            xen_be_printf(xendev, 1, "frontend state: %s -> %s\n",
                          xenbus_strstate(xendev->fe_state),
                          xenbus_strstate(fe_state));
        }
        xendev->fe_state = fe_state;
    }
    if (node == NULL  ||  strcmp(node, "protocol") == 0) {
        g_free(xendev->protocol);
        xendev->protocol = xenstore_read_fe_str(xendev, "protocol");
        if (xendev->protocol) {
            xen_be_printf(xendev, 1, "frontend protocol: %s\n",
                          xendev->protocol);
        }
    }

    if (node) {
        xen_be_printf(xendev, 2, "frontend update: %s\n", node);
        if (xendev->ops->frontend_changed) {
            xendev->ops->frontend_changed(xendev, node);
        }
    }
}

static void xenstore_update_be(char *watch, char *type, int dom,
                        struct XenDevOps *ops)
{
    struct XenDevice *xendev;
    char path[XEN_BUFSIZE], *bepath;
    unsigned int len, dev;

    len = snprintf(path, sizeof(path), "backend/%s/%d", type, dom);

    if (strstr(watch, path) == NULL) {
        return;
    }
    if (sscanf(watch+len, "/%u/%255s", &dev, path) != 2) {
        strcpy(path, "");
        if (sscanf(watch+len, "/%u", &dev) != 1) {
            dev = -1;
        }
    }
    if (dev == -1) {
        return;
    }

    xendev = xen_be_get_xendev(type, dom, dev, ops);
    if (xendev != NULL) {
        bepath = xs_read(xenstore, 0, xendev->be, &len);
        if (bepath == NULL) {
            xen_del_xendev(dom, dev);
        } else {
            free(bepath);
            xen_be_backend_changed(xendev, path);
            if (!(ops->flags & DEVOPS_FLAG_FE)) {
                xen_be_check_state(xendev);
            }
        }
    }
}

static void xenstore_update_fe(char *watch, struct XenDevice *xendev)
{
    char *node;
    unsigned int len;

    len = strlen(xendev->fe);
    if (strncmp(xendev->fe, watch, len) != 0) {
        return;
    }
    if (watch[len] != '/') {
        return;
    }
    node = watch + len + 1;

    xen_be_frontend_changed(xendev, node);
    xen_be_check_state(xendev);
}

static void xenstore_update(void *unused)
{
    char **vec = NULL;
    intptr_t type, ops, ptr;
    unsigned int dom, count;

    vec = xs_read_watch(xenstore, &count);
    if (vec == NULL) {
        goto cleanup;
    }

    if (sscanf(vec[XS_WATCH_TOKEN], "be:%" PRIxPTR ":%d:%" PRIxPTR,
               &type, &dom, &ops) == 3) {
        xenstore_update_be(vec[XS_WATCH_PATH], (void *)type, dom, (void *)ops);
    }
    if (sscanf(vec[XS_WATCH_TOKEN], "fe:%" PRIxPTR, &ptr) == 1) {
        xenstore_update_fe(vec[XS_WATCH_PATH], (void *)ptr);
    }

cleanup:
    free(vec);
}

int xen_be_init(void)
{
    xenstore = xs_daemon_open();
    if (!xenstore) {
        xen_be_printf(NULL, 0, "can't connect to xenstored\n");
        return -1;
    }

    if (qemu_set_fd_handler(xs_fileno(xenstore), xenstore_update,
        NULL, NULL) < 0) {
        goto err;
    }

    if (xen_xc == XC_HANDLER_INITIAL_VALUE) {

        /* Check if xen_init() have been called */
        goto err;
    }
    return 0;

err:
    qemu_set_fd_handler(xs_fileno(xenstore), NULL, NULL, NULL);
    xs_daemon_close(xenstore);
    xenstore = NULL;

    return -1;
}
