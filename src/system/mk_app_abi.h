/**
 * @file  mk_app_abi.h
 * @brief MeowKit native-app ABI — the stable C interface between the firmware
 *        and signed native ELF apps loaded from the SD card.
 *
 * This is the ONLY surface a native app may call. It is a flat C ABI on purpose:
 * apps are plain C, compiled standalone and linked against nothing — every
 * function here is resolved at load time against the firmware's exported symbol
 * table (see app_sdk.cpp). Apps must NOT pull in LVGL / LovyanGFX / the drivers;
 * they call these wrappers instead.
 *
 * Shared verbatim by the firmware (app_sdk.cpp implements it) and by each app
 * (build_app.sh puts this dir on the include path). Keep it pure C, no deps.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── ABI version ─────────────────────────────────────────────────────────
 * Apps are ELF files loaded from the SD card, so the app and the firmware are
 * updated independently. Any change to a struct in this header silently
 * shifts field offsets for an app built against a different revision, and the
 * symptom is not a crash — it is a screen quietly reading the wrong bytes and
 * a control that appears to do nothing.
 *
 * Bump this on ANY change to a struct layout or an enum value here. An app
 * should compare mk_abi_version() against the MK_ABI_VERSION it compiled with
 * and refuse to run on a mismatch, which turns a baffling misbehaviour into
 * one clear message. */
#define MK_ABI_VERSION 4

uint32_t mk_abi_version(void);

/* ── Colors (0xRRGGBB) ─────────────────────────────────────────────────── */
#define MK_COL_BLACK   0x000000u
#define MK_COL_WHITE   0xFFFFFFu
#define MK_COL_ACCENT  0xFF2A3Du   /* FeralCat red */
#define MK_COL_TEXT    0xFFFFFFu
#define MK_COL_MUTED   0x888888u
#define MK_COL_OK      0x00DD44u
#define MK_COL_WARN    0xFFAA00u
#define MK_COL_ERR     0xFF3333u
#define MK_COL_ACCENT_DARK 0x2E0009u
#define MK_COL_ACCENT_DIM  0x8A0016u   /* dim red — inactive radar rings */
#define MK_COL_ITEM_BG     0x1A1A1Au
#define MK_COL_BORDER      0x333333u

/* ── Buttons ───────────────────────────────────────────────────────────── */
enum {
    MK_BTN_A = 0, MK_BTN_B,
    MK_BTN_UP, MK_BTN_DOWN, MK_BTN_LEFT, MK_BTN_RIGHT
};

/* ── WiFi access-point record ──────────────────────────────────────────── */
typedef struct {
    char    ssid[33];
    int8_t  rssi;
    uint8_t channel;
    uint8_t encrypted;   /* 0/1 */
    uint8_t auth;        /* 0=Open 1=WEP 2=WPA 3=WPA2 4=WPA/2 5=EAP 6=WPA3 7=WPA2/3 */
    uint8_t bssid[6];
} mk_ap_t;

/* ── Layout (matches the built-in UI, 320x240) ─────────────────────────── */
#define MK_SCREEN_W    320
#define MK_SCREEN_H    240
#define MK_HDR_H       24
#define MK_ITEM_H      32
#define MK_CONTENT_Y   (MK_HDR_H + 1)
#define MK_PAD         8

/* ── Display ───────────────────────────────────────────────────────────────
 * The firmware owns an offscreen canvas. Draw into it, then present() blits it
 * to the LCD in one shot. */
void mk_gfx_clear(void);
void mk_gfx_header(const char* title);
void mk_gfx_footer(const char* left, const char* right);
void mk_gfx_menu_item(int row, const char* name, const char* value, int selected);
void mk_gfx_text(int x, int y, const char* s, uint32_t color);
void mk_gfx_text_sz(int x, int y, const char* s, uint32_t color, int size);  /* size 1|2 */
void mk_gfx_fill_rect(int x, int y, int w, int h, uint32_t color);
void mk_gfx_rect(int x, int y, int w, int h, uint32_t color);               /* outline */
void mk_gfx_fill_round_rect(int x, int y, int w, int h, int r, uint32_t color);
void mk_gfx_circle(int x, int y, int r, uint32_t color);                  /* outline */
void mk_gfx_fill_circle(int x, int y, int r, uint32_t color);
void mk_gfx_fill_triangle(int x0,int y0,int x1,int y1,int x2,int y2, uint32_t color);
void mk_gfx_line(int x0, int y0, int x1, int y1, uint32_t color);
void mk_gfx_present(void);
int  mk_content_rows(void);   /* number of visible menu rows */

/* ── WiFi ──────────────────────────────────────────────────────────────── */
void mk_wifi_begin(void);
int  mk_wifi_scan(mk_ap_t* out, int max);   /* count, or <0 on error */

/* ── Deauth monitor (passive 802.11 deauth/disassoc detector) ──────────────
 * A firmware-owned service (promiscuous capture stays in firmware). The app
 * drives it (begin/loop/pause…) and polls stats/history/attackers. */
#define MK_DEAUTH_HIST       30
#define MK_DEAUTH_THRESHOLD  6

typedef struct {
    uint32_t total;
    uint16_t rate;
    uint16_t peak;
    uint8_t  channel;
    uint8_t  alert;      /* 0/1 */
    uint32_t uptime_s;
    uint8_t  running;    /* 0/1 */
} mk_deauth_stats_t;

typedef struct {
    uint8_t  mac[6];     /* frame source (the "attacker") */
    uint8_t  victim[6];
    uint16_t count;
    int8_t   rssi;
    uint8_t  channel;
} mk_attacker_t;

void mk_deauth_begin(void);
void mk_deauth_loop(void);
void mk_deauth_pause(void);
void mk_deauth_resume(void);
void mk_deauth_stop(void);
int  mk_deauth_running(void);
void mk_deauth_stats(mk_deauth_stats_t* out);
int  mk_deauth_history(uint16_t* out, int max);        /* up to MK_DEAUTH_HIST */
int  mk_deauth_attackers(mk_attacker_t* out, int max);

/* ── Beacon-flood monitor (Karma / rogue-AP flood detector) ────────────────── */
#define MK_FLOOD_HIST        30
#define MK_FLOOD_ALERT_UNIQ  25

typedef struct {
    uint32_t total;
    uint16_t rate;
    uint16_t uniq;
    uint16_t proberesp;
    uint16_t peak_uniq;
    uint8_t  alert;      /* 0/1 */
    uint8_t  channel;
    uint32_t uptime_s;
    uint8_t  running;    /* 0/1 */
} mk_flood_stats_t;

void mk_flood_begin(void);
void mk_flood_loop(void);
void mk_flood_pause(void);
void mk_flood_resume(void);
void mk_flood_stop(void);
int  mk_flood_running(void);
void mk_flood_stats(mk_flood_stats_t* out);
int  mk_flood_history(uint16_t* out, int max);         /* up to MK_FLOOD_HIST */

/* ── BLE-spam monitor (Apple/Google/MS/Samsung advert flood detector) ──────── */
#define MK_BLESPAM_HIST       30
#define MK_BLESPAM_THRESHOLD  12

typedef struct {
    uint32_t total;
    uint16_t rate;
    uint16_t peak;
    uint8_t  alert;      /* 0/1 */
    uint16_t apple;
    uint16_t google;
    uint16_t ms;
    uint16_t samsung;
    uint32_t uptime_s;
    uint8_t  running;    /* 0/1 */
} mk_blespam_stats_t;

void mk_blespam_begin(void);
void mk_blespam_loop(void);
void mk_blespam_pause(void);
void mk_blespam_resume(void);
void mk_blespam_stop(void);
int  mk_blespam_running(void);
void mk_blespam_stats(mk_blespam_stats_t* out);
int  mk_blespam_history(uint16_t* out, int max);       /* up to MK_BLESPAM_HIST */

/* ── Probe-request sniffer (passive 802.11 probe monitor) ──────────────────── */
#define MK_PROBE_HIST    30
#define MK_PROBE_MAXDEV  24

typedef struct {
    uint32_t total;
    uint16_t rate;
    uint16_t peak;
    uint16_t devices;
    uint8_t  channel;
    uint32_t uptime_s;
    uint8_t  running;    /* 0/1 */
} mk_probe_stats_t;

typedef struct {
    uint8_t  mac[6];
    char     ssid[33];
    uint16_t count;
    int8_t   rssi;
    uint8_t  channel;
} mk_probe_dev_t;

void mk_probe_begin(void);
void mk_probe_loop(void);
void mk_probe_pause(void);
void mk_probe_resume(void);
void mk_probe_stop(void);
int  mk_probe_running(void);
void mk_probe_stats(mk_probe_stats_t* out);
int  mk_probe_history(uint16_t* out, int max);         /* up to MK_PROBE_HIST */
int  mk_probe_devices(mk_probe_dev_t* out, int max);   /* up to MK_PROBE_MAXDEV */

/* ── Unwanted-tracker detector (AirTag / Tile / SmartTag) ──────────────────── */
#define MK_TRK_MAXTRK     24
#define MK_TRK_PERSIST_MS 60000
#define MK_TRK_RECENT_MS  30000
enum { MK_TRK_APPLE = 0, MK_TRK_TILE = 1, MK_TRK_SAMSUNG = 2 };

typedef struct {
    uint16_t nearby;
    uint16_t persistent;
    uint8_t  alert;      /* 0/1 */
    uint8_t  running;    /* 0/1 */
} mk_tracker_stats_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  type;       /* MK_TRK_* */
    int8_t   rssi;
    uint16_t count;
    uint32_t first_ms;
    uint32_t last_ms;
    uint32_t id;             /* stable, nonzero within this scan session */
    int16_t  filtered_rssi;  /* median + EWMA, in dBm */
    uint8_t  scan_fresh;     /* 1 = valid observation since last pause */
} mk_tracker_t;

/* Signal-finder state for a selected candidate (see mk_tracker_finder). */
enum { MK_TRK_LIVE = 0, MK_TRK_WAITING, MK_TRK_LOST, MK_TRK_PAUSED };
#define MK_TRK_HISTORY 48
typedef struct {
    uint8_t  has_target;     /* 0/1 */
    uint8_t  state;          /* MK_TRK_LIVE / WAITING / LOST / PAUSED */
    uint8_t  trend_ready;    /* 0/1 — enough samples for a trend */
    int8_t   trend;          /* -1 weaker · 0 steady · +1 stronger */
    int16_t  strength;       /* 0..100 relative received strength (not range) */
    int16_t  filtered_rssi;  /* dBm */
    uint32_t age_ms;         /* since last reception of the target */
    uint32_t target_id;
    uint8_t  mac[6];
    uint8_t  type;           /* MK_TRK_* */
    uint8_t  scan_fresh;     /* 0/1 */
    uint16_t history_count;  /* 0..MK_TRK_HISTORY */
    int16_t  history[MK_TRK_HISTORY];  /* oldest→newest filtered RSSI */
} mk_tracker_finder_t;

void mk_tracker_begin(void);
void mk_tracker_loop(void);
void mk_tracker_pause(void);
void mk_tracker_resume(void);
void mk_tracker_stop(void);
int  mk_tracker_running(void);
int  mk_tracker_starting(void);                        /* 1 while BLE scan spins up */
int  mk_tracker_error(char* out, int max);             /* 1 + copies reason if failed */
void mk_tracker_stats(mk_tracker_stats_t* out);
int  mk_tracker_list(mk_tracker_t* out, int max);      /* up to MK_TRK_MAXTRK */
int  mk_tracker_select(uint32_t id);                   /* 0 releases; 1 if present */
void mk_tracker_finder(mk_tracker_finder_t* out);      /* finder state for selection */

/* ── WiFi Fox Hunt — follow one 802.11 target by signal ───────────────────
 * Builds a target list from beacons/probe-responses (APs, with SSID) and
 * data/probe-request frames (stations), then follows one selected target.
 * The finder state reuses mk_tracker_finder_t: identical semantics to the BLE
 * tracker radar, so both radios behave the same. Receive-only. */
#define MK_FOX_MAX 32
enum { MK_FOX_AP = 0, MK_FOX_STA = 1 };

typedef struct {
    uint8_t  mac[6];
    char     ssid[33];       /* APs only; "" for stations */
    uint8_t  kind;           /* MK_FOX_* */
    uint8_t  channel;
    int8_t   rssi;
    int16_t  filtered_rssi;  /* median + EWMA, dBm */
    uint16_t count;
    uint32_t id;             /* stable within a session */
} mk_fox_target_t;

typedef struct {
    uint16_t targets;
    uint16_t aps;
    uint16_t stations;
    uint8_t  channel;
    uint8_t  hopping;   /* 0/1 */
    uint8_t  running;   /* 0/1 */
} mk_fox_stats_t;

void mk_fox_begin(void);
void mk_fox_loop(void);
void mk_fox_pause(void);
void mk_fox_resume(void);
void mk_fox_stop(void);
int  mk_fox_running(void);
void mk_fox_stats(mk_fox_stats_t* out);
int  mk_fox_list(mk_fox_target_t* out, int max);   /* strongest first */
int  mk_fox_select(uint32_t id);                   /* 0 releases; 1 if present */
void mk_fox_finder(mk_tracker_finder_t* out);
void mk_fox_set_channel(int channel);              /* 0 = resume hopping */

/* ── WPA/WPA2 EAPOL + PMKID capture ──────────────────────────────────────
 * Records EAPOL-Key frames to /pcap/eapol_NNN.pcap and appends any PMKID to
 * /pcap/pmkid.22000 (hashcat WPA*01). For auditing passphrase strength on
 * networks you may test. Receive-only — it cannot force a handshake. */
#define MK_EAPOL_MAX 16
#define MK_EAPOL_M1          1
#define MK_EAPOL_M2          2
#define MK_EAPOL_M3          4
#define MK_EAPOL_M4          8
#define MK_EAPOL_SAE_COMMIT  16   /* WPA3 SAE commit  (auth alg 3, seq 1) */
#define MK_EAPOL_SAE_CONFIRM 32   /* WPA3 SAE confirm (auth alg 3, seq 2) */

/* Why a start attempt failed, so the UI can say something specific. */
enum { MK_EAPOL_ERR_NONE = 0, MK_EAPOL_ERR_MEM, MK_EAPOL_ERR_DIR,
       MK_EAPOL_ERR_FULL, MK_EAPOL_ERR_OPEN, MK_EAPOL_ERR_WRITE,
       MK_EAPOL_ERR_PROMISC };

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  msgs;         /* MK_EAPOL_M* bitmask */
    uint8_t  have_pmkid;   /* 0/1 */
    uint8_t  pmkid[16];
    int8_t   rssi;
    uint8_t  channel;
} mk_eapol_target_t;

typedef struct {
    uint32_t frames;
    uint16_t targets;
    uint16_t pmkids;
    uint16_t handshakes;   /* pairs with at least M1+M2 */
    uint16_t sae;          /* pairs with SAE commit+confirm */
    uint16_t dropped;
    uint8_t  channel;
    uint8_t  hopping;      /* 0/1 */
    uint8_t  running;      /* 0/1 */
    uint8_t  error;        /* MK_EAPOL_ERR_* — last begin() failure */
    char     path[40];
} mk_eapol_stats_t;

int  mk_eapol_begin(int hop, int channel);
void mk_eapol_loop(void);
void mk_eapol_pause(void);
void mk_eapol_resume(void);
void mk_eapol_stop(void);
int  mk_eapol_running(void);
void mk_eapol_stats(mk_eapol_stats_t* out);
int  mk_eapol_list(mk_eapol_target_t* out, int max);   /* newest first */
void mk_eapol_set_channel(int channel);

/* ── Evil-twin / captive-portal detection ────────────────────────────────
 * Passive half: repeated scans grouped by SSID, flagging the patterns a
 * legitimate multi-AP deployment does not produce. Active half (opt-in, one
 * network at a time): joins a chosen OPEN network and fetches a known-204
 * endpoint over cleartext — the same connectivity check every phone performs —
 * so an intercepting portal shows up as a redirect or a page body.
 * Finds portals; does not create them. */
#define MK_PD_MAX  24
#define MK_PD_PER  4

#define MK_PD_OPEN_CLONE     (1u << 0)   /* SSID offered open AND secured    */
#define MK_PD_MULTI_OUI      (1u << 1)   /* BSSIDs from unrelated vendors    */
#define MK_PD_AUTH_DOWNGRADE (1u << 2)   /* security weaker than first seen  */
#define MK_PD_MULTI_CHANNEL  (1u << 3)   /* widely separated channels (info) */
#define MK_PD_SIGNAL_JUMP    (1u << 4)   /* open clone as loud as the real AP*/

enum { MK_PD_PROBE_IDLE = 0, MK_PD_PROBE_CONNECTING, MK_PD_PROBE_CHECKING,
       MK_PD_PROBE_DONE, MK_PD_PROBE_FAILED };
enum { MK_PD_VERDICT_NONE = 0, MK_PD_VERDICT_CLEAR, MK_PD_VERDICT_PORTAL,
       MK_PD_VERDICT_INTERCEPT, MK_PD_VERDICT_NONET };

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    int8_t  rssi;
    uint8_t auth;            /* same encoding as mk_ap_t.auth */
} mk_pd_bssid_t;

typedef struct {
    char          ssid[33];
    uint8_t       n_bssid;
    uint16_t      flags;     /* MK_PD_* */
    int8_t        best_rssi;
    uint8_t       first_auth;
    mk_pd_bssid_t ap[MK_PD_PER];
} mk_pd_ssid_t;

typedef struct {
    uint16_t ssids;
    uint16_t flagged;
    uint16_t scans;
    uint8_t  scanning;   /* 0/1 */
    uint8_t  running;    /* 0/1 */

    /* Why a scan produced nothing. Zero SSIDs can mean the scan never
     * started (scan_rc != -1), started and failed (complete_rc < 0), or
     * succeeded and was dropped by the table (raw_seen > 0, accepted 0). */
    int16_t  scan_rc;
    int16_t  complete_rc;
    uint16_t raw_seen;
    uint16_t accepted;
    uint16_t rej_hidden;
    uint16_t rej_full;
    uint16_t rej_bssid;
    uint8_t  table_ok;   /* 0/1 */
} mk_pd_stats_t;

/* Rogue evidence. A portal verdict says what the network does; these say
 * whether it looks hostile. Every venue portal in the world is a portal. */
#define MK_PD_RG_SOFTAP_GW    (1u << 0)  /* gateway is 192.168.4.1          */
#define MK_PD_RG_IP_REDIRECT  (1u << 1)  /* redirected to a bare IP         */
#define MK_PD_RG_DNS_WILDCARD (1u << 2)  /* invented hostname resolves      */
#define MK_PD_RG_NO_SERVER    (1u << 3)  /* no Server: header               */
#define MK_PD_RG_FAST_LOCAL   (1u << 4)  /* answered too fast to be upstream*/
#define MK_PD_RG_OPEN_CLONE   (1u << 5)  /* SSID also exists secured        */
#define MK_PD_RG_SIGNAL_JUMP  (1u << 6)  /* clone louder than the real AP   */
#define MK_PD_RG_MULTI_OUI    (1u << 7)  /* same SSID across vendor OUIs    */

typedef struct {
    char     ssid[33];
    uint8_t  state;          /* MK_PD_PROBE_*   */
    uint8_t  verdict;        /* MK_PD_VERDICT_* */
    int16_t  http_code;
    char     redirect[64];
    uint32_t elapsed_ms;

    uint16_t rogue_flags;    /* MK_PD_RG_*      */
    uint8_t  rogue_conf;     /* 0-100           */
    char     gateway[16];
    char     server[24];
    uint16_t rtt_ms;
} mk_pd_probe_t;

void mk_pd_begin(void);
void mk_pd_loop(void);
void mk_pd_stop(void);
int  mk_pd_running(void);
void mk_pd_stats(mk_pd_stats_t* out);
int  mk_pd_list(mk_pd_ssid_t* out, int max);   /* flagged first, then strongest */

/* Open networks only; never sends a passphrase. 1 = probe started. */
int  mk_pd_probe_begin(const char* ssid);
void mk_pd_probe_stop(void);
void mk_pd_probe(mk_pd_probe_t* out);

/* ── Rogue-tool detection ────────────────────────────────────────────────
 * Finds other people's hacking hardware nearby — Flipper Zero, Pwnagotchi,
 * WiFi Pineapple, deauthers, and ESP32 tool firmwares (Bruce, Marauder).
 * Passive on both radios; WiFi and BLE are separate modes because the radios
 * contend.
 *
 * Hits carry their evidence, not just a verdict. An Espressif OUI proves
 * nothing alone — every ESP32 shares those prefixes, this device included — so
 * it only ever corroborates. Behaviour is the strong signal: one BSSID
 * advertising many SSIDs is Karma, and a station emitting deauth is attacking
 * whatever it calls itself. OUI or beaconing alone never raises a hit. */
#define MK_TD_MAX 24

enum { MK_TD_UNKNOWN = 0, MK_TD_PINEAPPLE, MK_TD_PWNAGOTCHI, MK_TD_DEAUTHER,
       MK_TD_MARAUDER, MK_TD_BRUCE, MK_TD_FLIPPER, MK_TD_ESP_TOOL };

#define MK_TD_EV_NAME      (1u << 0)
#define MK_TD_EV_OUI       (1u << 1)
#define MK_TD_EV_MULTISSID (1u << 2)
#define MK_TD_EV_DEAUTH_TX (1u << 3)
#define MK_TD_EV_BEACON_TX (1u << 4)
#define MK_TD_EV_JSON_SSID (1u << 5)
#define MK_TD_EV_SVC_UUID  (1u << 6)
#define MK_TD_EV_MFG       (1u << 7)
#define MK_TD_EV_SOFTAP    (1u << 8)   /* open net + non-ascending rates */

enum { MK_TD_MODE_WIFI = 0, MK_TD_MODE_BLE = 1 };

typedef struct {
    uint8_t  mac[6];
    uint8_t  kind;         /* MK_TD_* */
    uint8_t  radio;        /* MK_TD_MODE_* */
    uint8_t  confidence;   /* 0..100 */
    int8_t   rssi;
    uint8_t  channel;
    char     label[33];    /* SSID or BLE name */
    uint16_t ssid_count;
    uint16_t count;
    uint16_t ad_mask;      /* BLE: AD types seen (bit0 flags, 1 uuid16,
                            * 3 uuid128, 4 name, 8 mfg, 15 other)        */
    uint16_t mfg_id;       /* BLE: manufacturer company id, 0 if none    */
    uint16_t uuid16;       /* BLE: first 16-bit service UUID, 0 if none  */
    uint32_t evidence;     /* MK_TD_EV_* */
    uint32_t first_ms;
    uint32_t last_ms;
} mk_td_hit_t;

typedef struct {
    uint16_t hits;
    uint16_t high_conf;    /* confidence >= 70 */
    uint16_t tracked;
    uint8_t  mode;
    uint8_t  channel;
    uint8_t  hopping;      /* 0/1 */
    uint8_t  running;      /* 0/1 */
    uint8_t  ble_error;    /* 0/1 */
} mk_td_stats_t;

int  mk_td_begin(int mode);     /* MK_TD_MODE_*; 1 = started */
void mk_td_loop(void);
void mk_td_stop(void);
int  mk_td_running(void);
void mk_td_stats(mk_td_stats_t* out);
int  mk_td_list(mk_td_hit_t* out, int max);   /* highest confidence first */
void mk_td_set_channel(int channel);          /* 0 = resume hopping */

/* ── Crash breadcrumbs ───────────────────────────────────────────────────
 *
 * The last breadcrumb set before the device went down, kept in RTC RAM so it
 * survives a panic reboot, plus why it reset. Lets an app show where the
 * previous run died without a serial console attached. */
unsigned    mk_crumb_last_id(void);
const char* mk_crumb_last_name(void);
unsigned    mk_crumb_reset_id(void);
const char* mk_crumb_reset_str(void);

/* ── Per-AP security audit from beacon IEs ───────────────────────────────
 * Parses the RSN, WPA1 and WPS elements the scan API throws away, and reports
 * assessment findings: WPS left unlocked, PMF not required (so management
 * frames are unprotected), WPA3 running in downgradable transition mode, TKIP
 * or WEP still enabled, hidden SSIDs. Entirely passive. */
#define MK_WA_MAX 32

#define MK_WA_OPEN            (1u << 0)
#define MK_WA_WEP             (1u << 1)
#define MK_WA_WPA1            (1u << 2)
#define MK_WA_TKIP            (1u << 3)
#define MK_WA_WPS_ENABLED     (1u << 4)
#define MK_WA_WPS_UNLOCKED    (1u << 5)
#define MK_WA_NO_PMF          (1u << 6)
#define MK_WA_PMF_OPTIONAL    (1u << 7)
#define MK_WA_WPA3_TRANSITION (1u << 8)
#define MK_WA_HIDDEN          (1u << 9)
#define MK_WA_OWE             (1u << 10)
#define MK_WA_PMF_REQUIRED    (1u << 11)
#define MK_WA_SAE             (1u << 12)
#define MK_WA_HIDDEN_RESOLVED (1u << 13)
#define MK_WA_SOFTAP_RATES (1u << 14)  /* ESP-IDF SoftAP rate ordering */

/* Notable beacon IEs — an AP's radio-stack fingerprint. A bare ESP32 SoftAP
 * (what an evil portal or a hobby tool runs) advertises far fewer of these
 * than a commercial router. Reported, not judged. */
#define MK_WA_IE_COUNTRY (1u << 0)
#define MK_WA_IE_HT      (1u << 1)
#define MK_WA_IE_HTOP    (1u << 2)
#define MK_WA_IE_VHT     (1u << 3)
#define MK_WA_IE_EXTCAP  (1u << 4)
#define MK_WA_IE_RM      (1u << 5)
#define MK_WA_IE_POWER   (1u << 6)
#define MK_WA_IE_WMM     (1u << 7)
#define MK_WA_IE_WPS     (1u << 8)
#define MK_WA_IE_MOBDOM  (1u << 9)

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint32_t flags;        /* MK_WA_* */
    uint16_t pairwise;
    uint16_t group;
    uint32_t akm;
    uint8_t  wps_state;    /* 0 none, 1 unconfigured, 2 configured */
    uint8_t  wps_locked;   /* 0 no, 1 yes, 0xFF unknown */
    uint8_t  findings;     /* count of serious flags */
    uint8_t  ie_count;     /* information elements in the beacon */
    uint8_t  ie_vendor;    /* how many were vendor-specific      */
    uint16_t ie_mask;      /* MK_WA_IE_* present                 */
} mk_wa_ap_t;

typedef struct {
    uint16_t aps;
    uint16_t at_risk;
    uint16_t wps_open;
    uint16_t no_pmf;
    uint8_t  channel;
    uint8_t  hopping;   /* 0/1 */
    uint8_t  running;   /* 0/1 */
} mk_wa_stats_t;

void mk_wa_begin(void);
void mk_wa_loop(void);
void mk_wa_pause(void);
void mk_wa_resume(void);
void mk_wa_stop(void);
int  mk_wa_running(void);
void mk_wa_stats(mk_wa_stats_t* out);
int  mk_wa_list(mk_wa_ap_t* out, int max);     /* worst findings first */
void mk_wa_set_channel(int channel);           /* 0 = resume hopping */

/* ── Evil twin + captive portal (ACTIVE: brings up an AP) ────────────────
 * Advertises an OPEN SoftAP under the given SSID, hijacks DNS, and serves a
 * portal page from /portal/<name>.html. Associations and form submissions are
 * logged to /portal/captures.csv.
 *
 * This impersonates a network and records what people type into it. Run it
 * only under an engagement whose scope covers social-engineering testing of
 * the site and population being tested. The capture file is plaintext client
 * credential material — handle and destroy it accordingly. */
#define MK_TWIN_CLIENTS 16
#define MK_TWIN_CAPS    16

typedef struct {
    uint8_t  mac[6];
    uint32_t joined_ms;
    uint8_t  submitted;   /* 0/1 */
} mk_twin_client_t;

typedef struct {
    uint8_t  mac[6];
    uint32_t ms;
    char     field1[48];
    char     field2[48];
} mk_twin_cap_t;

typedef struct {
    char     ssid[33];
    char     portal[32];
    uint16_t clients;
    uint16_t seen;
    uint16_t submits;
    uint32_t requests;
    uint8_t  channel;
    uint8_t  running;   /* 0/1 */
    uint8_t  sd_ok;     /* 0/1 — capture log writable */
} mk_twin_stats_t;

/* portal may be NULL/"" to use the built-in page. 1 = the AP came up. */
int  mk_twin_begin(const char* ssid, const char* portal, int channel);
void mk_twin_loop(void);           /* services DNS + HTTP — call every loop */
void mk_twin_stop(void);
int  mk_twin_running(void);
void mk_twin_stats(mk_twin_stats_t* out);
int  mk_twin_clients(mk_twin_client_t* out, int max);
int  mk_twin_captures(mk_twin_cap_t* out, int max);   /* newest first */
void mk_twin_clear(void);

/* ── Raw 802.11 capture to SD (PCAP) ──────────────────────────────────────
 * A firmware-owned capture service. Promiscuous RX buffers frames in PSRAM and
 * the drain to /pcap/cap_NNN.pcap happens in mk_pcap_loop(), so the app must
 * call that regularly or frames are dropped. Frames carry a minimal radiotap
 * header (channel + RSSI), so Wireshark shows per-frame signal.
 * Receive-only: nothing here transmits. */
#define MK_PCAP_HIST 30

typedef struct {
    uint32_t frames;     /* frames written to the file            */
    uint32_t dropped;    /* frames lost because the ring was full */
    uint32_t bytes;      /* file size so far                      */
    uint16_t rate;       /* frames in the last completed second   */
    uint16_t peak;
    uint8_t  channel;
    uint8_t  hopping;    /* 0/1 — sweeping channels 1..13         */
    uint8_t  running;    /* 0/1                                   */
    uint8_t  pinned;     /* 0/1 — hops ignored; something else     */
                         /*       owns the radio (e.g. a SoftAP)   */
    uint32_t uptime_s;
    char     path[40];   /* e.g. "/pcap/cap_007.pcap"             */
} mk_pcap_stats_t;

/* hop = sweep 1..13; channel = fixed channel when hop is 0. 1 = started. */
int  mk_pcap_begin(int hop, int channel);
void mk_pcap_loop(void);              /* drains the ring — call every loop */
void mk_pcap_pause(void);
void mk_pcap_resume(void);
void mk_pcap_stop(void);              /* flush + close the file */
int  mk_pcap_running(void);
void mk_pcap_stats(mk_pcap_stats_t* out);
int  mk_pcap_history(uint16_t* out, int max);   /* up to MK_PCAP_HIST */
void mk_pcap_set_channel(int channel);          /* 0 = resume hopping */

/* ── Media / audio player (MeowPlayer) ─────────────────────────────────────
 * The audio engine (ES8311 DAC + Helix MP3 decoder + I2S on a core-0 worker)
 * stays in firmware; the app drives it with commands and polls a status
 * snapshot. Files are scanned from /music (.mp3). */
enum { MK_MEDIA_SCAN = 0, MK_MEDIA_PLAY, MK_MEDIA_PAUSE, MK_MEDIA_STOP,
       MK_MEDIA_VOLUME, MK_MEDIA_SEEK, MK_MEDIA_EQ };

typedef struct {
    char     state[16];   /* idle/scanning/loading/playing/paused/stopped/ended/error */
    char     title[96];
    uint32_t position;    /* seconds */
    uint32_t duration;    /* seconds (approx for MP3) */
    uint32_t generation;  /* bumps when a catalog scan completes */
    uint16_t tracks;
    uint8_t  volume;      /* 0..100 */
    uint32_t finished;    /* increments once on natural end-of-track */
} mk_media_status_t;

typedef struct {
    uint16_t id;          /* stable track id for MK_MEDIA_PLAY value */
    char     title[96];
} mk_track_t;

int  mk_media_begin(void);                 /* start engine; 1 = ok. Sets speaker on. */
void mk_media_end(void);                   /* stop engine + amp */
void mk_media_cmd(int action, int value);  /* MK_MEDIA_*; value = track id / volume / seek sec */
void mk_media_status(mk_media_status_t* out);
int  mk_media_tracks(int offset, mk_track_t* out, int max);  /* fills up to min(max,8); returns count */
void mk_media_set_output(int speaker);     /* 1 = speaker, 0 = headphone jack */
int  mk_tracker_beep(uint16_t duration_ms); /* short proximity cue; 0 when audio busy */

/* ── Input ─────────────────────────────────────────────────────────────── */
void mk_input_poll(void);       /* call once per loop before reading buttons */
int  mk_btn(int id);            /* 1 once per press (edge-triggered) */
int  mk_btn_long(int id);       /* 1 while the button is held long */

/* ── Misc ──────────────────────────────────────────────────────────────── */
void     mk_delay(uint32_t ms);
uint32_t mk_millis(void);
int      mk_snprintf(char* buf, size_t n, const char* fmt, ...);

#ifdef __cplusplus
}
#endif
