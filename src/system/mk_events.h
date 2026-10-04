/**
 * @file mk_events.h
 * @brief Lightweight system event bus (FreeRTOS queue, depth 16).
 *
 * Producers: launcher button polling, power_tick, SD hot-plug detection.
 * Consumers: launcher navigation handler, apps (optional).
 *
 * Design:
 *   - Single queue, single byte per event — minimal overhead.
 *   - Non-blocking pop: apps/launcher check in their onRunning() / onLoop().
 *   - Thread-safe: push can be called from any task or ISR (xQueueSendFromISR).
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Event types ──────────────────────────────────────────────── */
typedef enum {
    /* Physical buttons */
    MK_EVT_BTN_A          = 0x01,
    MK_EVT_BTN_B          = 0x02,
    MK_EVT_BTN_B_LONG     = 0x03,
    /* 5-way joystick */
    MK_EVT_JOY_UP         = 0x10,
    MK_EVT_JOY_DOWN       = 0x11,
    MK_EVT_JOY_LEFT       = 0x12,
    MK_EVT_JOY_RIGHT      = 0x13,
    /* System */
    MK_EVT_POWER_LOW      = 0x20,   /* battery ≤ WARN_PCT while discharging */
    MK_EVT_SD_INSERTED    = 0x30,
    MK_EVT_SD_REMOVED     = 0x31,
    MK_EVT_TOUCH          = 0x40,   /* any touch event (for sleep timer reset) */
    MK_EVT_KEY_TONE,
} mk_event_t;

/* ── Lifecycle ────────────────────────────────────────────────── */

/** Create the queue. Call once before any push/pop (before LVGL init). */
void mk_events_init(void);

/* ── Producer API ─────────────────────────────────────────────── */

/** Push an event. Safe from any task or ISR. Silently drops if queue full. */
void mk_event_push(mk_event_t evt);

/* ── Consumer API ─────────────────────────────────────────────── */

/** Non-blocking pop. Returns true and fills *out if an event is available. */
bool mk_event_pop(mk_event_t* out);

/** Flush all pending events without processing (e.g., on screen transition). */
void mk_events_flush(void);

#ifdef __cplusplus
}
#endif
