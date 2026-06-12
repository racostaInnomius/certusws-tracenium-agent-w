/*
 * privsvc/linux/helpers/screencap.c
 *
 * tracenium-screencap — one-shot Linux (X11) screen capture helper for RCP.
 *
 * Invoked by the PrivSvc orchestrator (privsvc/linux/src/screen-capture.ts)
 * as the session user, with DISPLAY + XAUTHORITY in the environment:
 *
 *   runuser -u <user> -- env DISPLAY=:0 XAUTHORITY=<path> \
 *           tracenium-screencap --quality N
 *
 * Contract (one JSON line on stdout, nothing else):
 *   success: {"ok":true,"data":"<base64 jpeg>","width":W,"height":H,
 *             "cursorX":X,"cursorY":Y}
 *   failure: {"ok":false,"code":"<stable_code>","message":"..."}
 *
 * width/height + cursorX/Y are in X11 root-window pixels (the same space
 * XQueryPointer reports), so the operator UI's cursor overlay aligns.
 * Stable error codes mirror the cross-platform vocabulary:
 *   x11_connect_failed, screen_capture_no_display,
 *   screen_capture_failed, screen_capture_encode_failed, out_of_memory.
 *
 * Scope (initial landing):
 *   - X11 only. Wayland is rejected upstream in the orchestrator before
 *     this helper is ever spawned.
 *   - Captures the whole X root window (the union of all monitors).
 *     Per-monitor cropping (RandR) is a follow-up; this matches the
 *     single-frame simplicity of the Windows primary-only path.
 *
 * Build (see scripts/build-linux-binaries.sh):
 *   cc -O2 -Wall screencap.c -o tracenium-screencap -lX11 -ljpeg
 * Build deps: libx11-dev libjpeg-dev (Debian) / libX11-devel libjpeg-turbo-devel (RHEL).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <jpeglib.h>

/* ── Output helpers ──────────────────────────────────────────────────
 * `code` and `message` are always controlled literals (no quotes /
 * backslashes), and base64 uses a JSON-safe alphabet, so we can emit
 * without a full JSON escaper.
 */
static void emit_error(const char *code, const char *msg) {
    printf("{\"ok\":false,\"code\":\"%s\",\"message\":\"%s\"}\n", code, msg);
    fflush(stdout);
    exit(0); /* exit 0: the JSON IS the result; orchestrator reads `ok`. */
}

/* ── base64 ──────────────────────────────────────────────────────────*/
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *src, size_t len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(olen + 1);
    if (!out) return NULL;
    size_t i = 0, o = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t n = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1] << 8) | src[i + 2];
        out[o++] = B64[(n >> 18) & 63];
        out[o++] = B64[(n >> 12) & 63];
        out[o++] = B64[(n >> 6) & 63];
        out[o++] = B64[n & 63];
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t n = (uint32_t)src[i] << 16;
        out[o++] = B64[(n >> 18) & 63];
        out[o++] = B64[(n >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t n = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1] << 8);
        out[o++] = B64[(n >> 18) & 63];
        out[o++] = B64[(n >> 12) & 63];
        out[o++] = B64[(n >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

/* ── channel mask → (shift, bits) for extracting 8-bit components ─────*/
static void mask_shift(unsigned long mask, int *shift, int *bits) {
    int s = 0, b = 0;
    if (mask == 0) { *shift = 0; *bits = 0; return; }
    while (!(mask & 1UL)) { mask >>= 1; s++; }
    while (mask & 1UL) { mask >>= 1; b++; }
    *shift = s;
    *bits = b;
}

static inline unsigned char scale8(unsigned long v, int bits) {
    if (bits == 8) return (unsigned char)v;
    if (bits < 8) return (unsigned char)(v << (8 - bits));
    return (unsigned char)(v >> (bits - 8));
}

/* ── arg parse ───────────────────────────────────────────────────────*/
static int parse_quality(int argc, char **argv) {
    int q = 80;
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--quality") == 0) {
            q = atoi(argv[i + 1]);
            break;
        }
    }
    if (q < 1) q = 1;
    if (q > 100) q = 100;
    return q;
}

int main(int argc, char **argv) {
    int quality = parse_quality(argc, argv);

    /* Connect using DISPLAY (+ XAUTHORITY) from the environment the
     * orchestrator set up. */
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) {
        emit_error("x11_connect_failed",
                   "Could not open X display (check DISPLAY/XAUTHORITY for the active session)");
    }

    int screen = DefaultScreen(dpy);
    Window root = RootWindow(dpy, screen);

    XWindowAttributes attr;
    if (!XGetWindowAttributes(dpy, root, &attr)) {
        emit_error("screen_capture_no_display", "XGetWindowAttributes failed on root window");
    }
    int width = attr.width;
    int height = attr.height;
    if (width <= 0 || height <= 0) {
        emit_error("screen_capture_no_display", "Root window has zero size");
    }

    XImage *img = XGetImage(dpy, root, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!img) {
        emit_error("screen_capture_failed", "XGetImage returned NULL");
    }

    int rs, rb, gs, gb, bs, bb;
    mask_shift(img->red_mask, &rs, &rb);
    mask_shift(img->green_mask, &gs, &gb);
    mask_shift(img->blue_mask, &bs, &bb);

    /* Cursor position in root coordinates. */
    int cursorX = -1, cursorY = -1;
    {
        Window root_ret, child_ret;
        int root_x, root_y, win_x, win_y;
        unsigned int mask_ret;
        if (XQueryPointer(dpy, root, &root_ret, &child_ret,
                          &root_x, &root_y, &win_x, &win_y, &mask_ret)) {
            cursorX = root_x;
            cursorY = root_y;
        }
    }

    /* ── JPEG encode into memory ─────────────────────────────────────*/
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr); /* default error_exit() aborts the
                                        * process on a fatal libjpeg error;
                                        * the orchestrator then sees no/partial
                                        * output and maps it to
                                        * screen_capture_no_output. */
    jpeg_create_compress(&cinfo);

    unsigned char *jpeg_buf = NULL;
    unsigned long jpeg_size = 0;
    jpeg_mem_dest(&cinfo, &jpeg_buf, &jpeg_size);

    cinfo.image_width = width;
    cinfo.image_height = height;
    cinfo.input_components = 3;
    cinfo.in_color_space = JCS_RGB;
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, quality, TRUE);
    jpeg_start_compress(&cinfo, TRUE);

    unsigned char *row = (unsigned char *)malloc((size_t)width * 3);
    if (!row) {
        XDestroyImage(img);
        emit_error("out_of_memory", "Could not allocate scanline buffer");
    }

    while (cinfo.next_scanline < (JDIMENSION)height) {
        int y = cinfo.next_scanline;
        for (int x = 0; x < width; x++) {
            unsigned long px = XGetPixel(img, x, y);
            row[x * 3 + 0] = scale8((px & img->red_mask) >> rs, rb);
            row[x * 3 + 1] = scale8((px & img->green_mask) >> gs, gb);
            row[x * 3 + 2] = scale8((px & img->blue_mask) >> bs, bb);
        }
        JSAMPROW rp = row;
        jpeg_write_scanlines(&cinfo, &rp, 1);
    }

    jpeg_finish_compress(&cinfo);
    free(row);
    XDestroyImage(img);
    XCloseDisplay(dpy);

    char *b64 = base64_encode(jpeg_buf, jpeg_size);
    jpeg_destroy_compress(&cinfo); /* frees jpeg_buf (allocated via jpeg_mem_dest) */

    if (!b64) {
        emit_error("out_of_memory", "Could not base64-encode JPEG");
    }

    /* One JSON line. `data` is large (often MBs); print it in one go. */
    printf("{\"ok\":true,\"data\":\"%s\",\"width\":%d,\"height\":%d,\"cursorX\":%d,\"cursorY\":%d}\n",
           b64, width, height, cursorX, cursorY);
    fflush(stdout);
    free(b64);
    return 0;
}
