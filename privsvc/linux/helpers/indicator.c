/*
 * privsvc/linux/helpers/indicator.c
 *
 * tracenium-indicator — indicador PERMANENTE de sesión de control remoto para
 * Linux/X11 (ADR-0012, paso 1).
 *
 * Windows tiene bandeja (.NET) y macOS tiene app de estado (Swift). Linux no
 * tiene NADA en la sesión del usuario: el paquete instala dos servicios de
 * sistema y se acabó. Así que el indicador no puede vivir en una bandeja que
 * no existe — lo lanza PrivSvc dentro de la sesión gráfica, con la misma
 * maniobra que ya usa para capturar la pantalla (ver x11-session.ts), y vive
 * exactamente lo que dure la sesión remota.
 *
 * Esa dependencia tiene una propiedad que conviene entender: si el agente
 * muere, el indicador muere con él. Es lo correcto — un aviso huérfano que
 * dice "te están viendo" cuando ya nadie mira es una alarma falsa, y una
 * alarma falsa entrena a la gente a ignorar la siguiente.
 *
 * Invocación (por el orquestador, como el usuario de la sesión):
 *
 *   runuser -u <user> -- env DISPLAY=:0 XAUTHORITY=<path> \
 *           tracenium-indicator --session-id <id> --text "<texto>" \
 *                               --button "<etiqueta>"
 *
 * Contrato de arranque (una línea JSON en stdout, y nada más):
 *   listo:  {"ok":true}
 *   fallo:  {"ok":false,"code":"<código estable>","message":"..."}
 *
 * Esa línea NO es decorativa: el orquestador espera a leerla antes de dejar
 * que empiece la captura. Si no llega, no se comparte pantalla. Sin esa
 * confirmación estaríamos lanzando el aviso y esperando que apareciera, que
 * es justo la clase de suposición que hace que un control de privacidad
 * funcione en las pruebas y no en el equipo de alguien.
 *
 * Códigos estables:
 *   x11_connect_failed, indicator_no_font, indicator_window_failed
 *
 * Salida:
 *   - Al cerrarse stdin (el padre murió o lo cerró): sale. Es la correa que
 *     impide que el aviso sobreviva al agente.
 *   - Al pulsar el botón: escribe la petición de corte y sigue en pantalla
 *     con "Stopping…" hasta que el agente lo cierre. No desaparece solo: si
 *     lo hiciera, la persona vería irse el aviso mientras la sesión aún vive
 *     medio segundo más, que es exactamente la mentira que no podemos contar.
 *
 * Build (ver scripts/build-linux-binaries.sh):
 *   cc -O2 -Wall indicator.c -o tracenium-indicator -lX11
 *
 * Solo libX11: NO usamos Xft/fontconfig a propósito. Añadirlo arrastraría
 * freetype y fontconfig como dependencias del .deb/.rpm para dibujar dos
 * líneas de texto. Con fuentes core el texto es más feo y el paquete no crece.
 */

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BANNER_HEIGHT 34
#define BANNER_MAX_WIDTH 720
#define BUTTON_PAD_X 12
#define BUTTON_MARGIN 8

/* Ámbar de aviso, el mismo par que la bandeja de Windows y la banda de macOS.
 * Ámbar y no rojo: el rojo dice "error" y esto no lo es — es una sesión
 * legítima que la persona debe poder ver. El rojo se guarda para cuando algo
 * va mal de verdad. */
#define COLOR_BG   "#FFF4D6"
#define COLOR_FG   "#8B6404"
#define COLOR_BTN  "#FFFFFF"

static Display *dpy = NULL;
static Window win = 0;
static GC gc = 0;
static XFontStruct *font = NULL;
static unsigned long col_bg, col_fg, col_btn;
static int win_w = BANNER_MAX_WIDTH;
static int btn_x = 0, btn_w = 0;

static char text_buf[512] = "A remote operator is viewing this screen";
static char button_buf[64] = "Stop sharing";
static char session_id[128] = "";
static int stopping = 0;

static void emit_error(const char *code, const char *message) {
    printf("{\"ok\":false,\"code\":\"%s\",\"message\":\"%s\"}\n", code, message);
    fflush(stdout);
}

/*
 * Escribe la petición de corte en $HOME/.config/tracenium/.
 *
 * Ese es el sitio exacto donde el agente la busca (ver
 * src/status/remote-session-revoke.ts).
 *
 * El orquestador nos pasa HOME EXPLÍCITAMENTE en el entorno, resuelto con
 * getent, en vez de confiar en lo que runuser deje puesto. Si HOME acabara
 * siendo el de root, este fichero iría a /root/.config —donde el agente no
 * mira— y el botón "detener" no daría error: no haría NADA. Un control de
 * privacidad que falla en silencio es peor que no tenerlo, porque la persona
 * se queda creyendo que cortó.
 *
 * Temp + rename: el agente sondea dos veces por segundo y no puede toparse
 * con un fichero a medio escribir. Un JSON corrupto en este canal significa
 * un corte que no ocurre, que es el peor fallo posible aquí.
 */
static void write_revoke_request(void) {
    const char *home = getenv("HOME");
    if (!home || !*home) return;

    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.config", home);
    mkdir(dir, 0700);
    snprintf(dir, sizeof(dir), "%s/.config/tracenium", home);
    mkdir(dir, 0700);

    char final_path[600], tmp_path[620];
    snprintf(final_path, sizeof(final_path), "%s/remote-session-revoke.json", dir);
    snprintf(tmp_path, sizeof(tmp_path), "%s/.remote-session-revoke.tmp", dir);

    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    const char *user = getenv("USER");
    if (!user || !*user) user = "";

    FILE *f = fopen(tmp_path, "w");
    if (!f) return;
    /* `by` va para el registro de auditoría: el corte lo pidió una persona en
     * el endpoint, no un fallo de red. Que esos dos casos se distingan es la
     * mitad del valor de tener el control. */
    fprintf(f, "{\"sessionId\":\"%s\",\"atUtc\":\"%s\",\"by\":\"%s\"}\n",
            session_id, stamp, user);
    fclose(f);
    chmod(tmp_path, 0600);

    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
    }
}

static int text_width(const char *s) {
    if (!font) return 0;
    return XTextWidth(font, s, (int)strlen(s));
}

static void draw(void) {
    if (!dpy || !win) return;

    XSetForeground(dpy, gc, col_bg);
    XFillRectangle(dpy, win, gc, 0, 0, (unsigned)win_w, BANNER_HEIGHT);

    /* Botón, anclado a la derecha. */
    const char *label = stopping ? "Stopping..." : button_buf;
    int lw = text_width(label);
    btn_w = lw + BUTTON_PAD_X * 2;
    btn_x = win_w - btn_w - BUTTON_MARGIN;
    int btn_y = (BANNER_HEIGHT - 22) / 2;

    XSetForeground(dpy, gc, col_btn);
    XFillRectangle(dpy, win, gc, btn_x, btn_y, (unsigned)btn_w, 22);
    XSetForeground(dpy, gc, col_fg);
    XDrawRectangle(dpy, win, gc, btn_x, btn_y, (unsigned)btn_w, 22);

    int baseline = font ? (BANNER_HEIGHT + font->ascent - font->descent) / 2 : BANNER_HEIGHT / 2;
    if (font) {
        XDrawString(dpy, win, gc, btn_x + BUTTON_PAD_X, baseline, label, (int)strlen(label));
    }

    /* Texto, centrado en el hueco que queda a la izquierda del botón. Si no
     * cabe se dibuja desde el margen y X lo recorta: preferimos un texto
     * cortado a no decir nada. */
    if (font) {
        int avail = btn_x - BUTTON_MARGIN * 2;
        int tw = text_width(text_buf);
        int tx = (tw < avail) ? (avail - tw) / 2 + BUTTON_MARGIN : BUTTON_MARGIN;
        XDrawString(dpy, win, gc, tx, baseline, text_buf, (int)strlen(text_buf));
    }

    XFlush(dpy);
}

static XFontStruct *load_font(void) {
    /* De más legible a más universal. "fixed" existe prácticamente en
     * cualquier servidor X; si tampoco está, es mejor fallar que enseñar una
     * barra de color sin texto, que no informa de nada. */
    static const char *candidates[] = {
        "-*-helvetica-bold-r-normal--12-*-*-*-*-*-iso8859-1",
        "-*-dejavu sans-bold-r-normal--12-*-*-*-*-*-*-*",
        "-*-*-bold-r-normal--12-*-*-*-*-*-iso8859-1",
        "9x15bold",
        "fixed",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        XFontStruct *f = XLoadQueryFont(dpy, candidates[i]);
        if (f) return f;
    }
    return NULL;
}

static unsigned long alloc_color(const char *spec, unsigned long fallback) {
    Colormap cmap = DefaultColormap(dpy, DefaultScreen(dpy));
    XColor c, exact;
    if (XAllocNamedColor(dpy, cmap, spec, &c, &exact)) return c.pixel;
    return fallback;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--session-id") && i + 1 < argc) {
            snprintf(session_id, sizeof(session_id), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--text") && i + 1 < argc) {
            snprintf(text_buf, sizeof(text_buf), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--button") && i + 1 < argc) {
            snprintf(button_buf, sizeof(button_buf), "%s", argv[++i]);
        }
    }

    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        emit_error("x11_connect_failed", "Could not open X display");
        return 1;
    }

    int screen = DefaultScreen(dpy);
    int sw = DisplayWidth(dpy, screen);

    font = load_font();
    if (!font) {
        emit_error("indicator_no_font", "No usable X core font found");
        XCloseDisplay(dpy);
        return 1;
    }

    col_bg = alloc_color(COLOR_BG, WhitePixel(dpy, screen));
    col_fg = alloc_color(COLOR_FG, BlackPixel(dpy, screen));
    col_btn = alloc_color(COLOR_BTN, WhitePixel(dpy, screen));

    win_w = sw - 40;
    if (win_w > BANNER_MAX_WIDTH) win_w = BANNER_MAX_WIDTH;
    if (win_w < 200) win_w = sw > 200 ? 200 : sw;
    int x = (sw - win_w) / 2;

    /*
     * override_redirect = True: el gestor de ventanas ni la decora ni la
     * gestiona, y queda por encima de las ventanas normales sin depender de
     * que el WM respete _NET_WM_STATE_ABOVE (muchos no lo hacen).
     *
     * El precio es que tampoco recibe foco de teclado, cosa que aquí es una
     * ventaja: la persona sigue escribiendo donde estaba, probablemente en
     * mitad de la incidencia que motivó la sesión de soporte.
     */
    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.override_redirect = True;
    attrs.background_pixel = col_bg;
    attrs.save_under = True;

    win = XCreateWindow(dpy, RootWindow(dpy, screen),
                        x, 0, (unsigned)win_w, BANNER_HEIGHT, 0,
                        CopyFromParent, InputOutput, CopyFromParent,
                        CWOverrideRedirect | CWBackPixel | CWSaveUnder, &attrs);
    if (!win) {
        emit_error("indicator_window_failed", "Could not create indicator window");
        XCloseDisplay(dpy);
        return 1;
    }

    gc = XCreateGC(dpy, win, 0, NULL);
    XSetFont(dpy, gc, font->fid);
    XSelectInput(dpy, win, ExposureMask | ButtonPressMask | StructureNotifyMask);
    XMapRaised(dpy, win);
    /* Pintar YA, sin esperar al primer Expose. La línea de abajo afirma que
     * el aviso está delante de la persona; si solo mapeáramos, esa
     * afirmación sería cierta unos milisegundos DESPUÉS de hacerla, y en
     * ese hueco el orquestador ya habría autorizado la captura. */
    draw();
    XFlush(dpy);

    /* Confirmación de que el aviso está EN PANTALLA. El orquestador espera
     * esta línea antes de permitir la captura. */
    printf("{\"ok\":true}\n");
    fflush(stdout);

    int xfd = ConnectionNumber(dpy);
    for (;;) {
        while (XPending(dpy)) {
            XEvent ev;
            XNextEvent(dpy, &ev);
            if (ev.type == Expose) {
                draw();
            } else if (ev.type == ButtonPress) {
                int px = ev.xbutton.x, py = ev.xbutton.y;
                if (!stopping && px >= btn_x && px <= btn_x + btn_w &&
                    py >= 0 && py <= BANNER_HEIGHT) {
                    /* Marcar ANTES de escribir: si la escritura tarda, la
                     * persona ya ve que se está actuando. Volver a pulsar no
                     * acelera nada. */
                    stopping = 1;
                    draw();
                    write_revoke_request();
                }
            }
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(xfd, &fds);
        FD_SET(STDIN_FILENO, &fds);
        int maxfd = xfd > STDIN_FILENO ? xfd : STDIN_FILENO;

        /* Timeout de 2 s: además de despertar para eventos, sirve de latido
         * para volver a subir la ventana. Una app que se abra a pantalla
         * completa DESPUÉS que nosotros puede quedar por encima, y un
         * indicador que se esconde justo cuando alguien abre a pantalla
         * completa lo que no quiere que le vean no es un indicador. */
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int r = select(maxfd + 1, &fds, NULL, NULL, &tv);

        if (r > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
            char buf[64];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break; /* EOF: el padre se fue. Nos vamos con él. */
        }

        if (r == 0) {
            XRaiseWindow(dpy, win);
            XFlush(dpy);
        }

        if (r < 0 && errno != EINTR) break;
    }

    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    return 0;
}
