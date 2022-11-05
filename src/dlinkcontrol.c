/*
 * Copyright 2022 Francesco Lattanzio
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <config.h>

#ifdef HAVE_WORKING_LIBCURL
#define USE_LIBCURL
#undef USE_FETCH
#elif defined(HAVE_LIBFETCH)
#undef USE_LIBCURL
#define USE_FETCH
#else
#error "No usable HTTP client library available"
#endif

#include <errno.h>

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <sys/time.h>
#include <sys/types.h>

#ifdef USE_LIBCURL
#include <curl/curl.h>
#endif

#ifdef USE_FETCH
#include <fetch.h>
#endif

#include "cJSON.h"


#define USAGE                                                           \
    PACKAGE_STRING "\n"                                                 \
    "\n"                                                                \
    "Usage: " PACKAGE_TARNAME " [-qs] [-h host] iccid\n"                \
    "       " PACKAGE_TARNAME " [-qs] [-h host] unlock <pin>\n"         \
    "       " PACKAGE_TARNAME " [-qs] [-h host] reset_pin <new_pin> <puk> [NOT TESTED!]\n" \
    "       " PACKAGE_TARNAME " [-qls] [-c cap] [-h host] connect <pid_file> <account_file>\n" \
    "       " PACKAGE_TARNAME " [-qs] [-h host] dns\n"                  \
    "       " PACKAGE_TARNAME " [-qs] [-h host] disconnect <pid_file>\n" \
    "       " PACKAGE_TARNAME " [-qs] [-h host] sms list <storage> <box>\n" \
    "       " PACKAGE_TARNAME " [-qs] [-h host] sms store <storage> <msisdn> <text>\n" \
    "       " PACKAGE_TARNAME " [-qs] [-h host] sms delete <storage> <box> <index>\n" \
    "    -c cap       - instead of logging the number of received and transmitted\n" \
    "                   bytes so far, logs the number of \"available\" bytes, i.e.,\n" \
    "                   the difference between the specified value and the sum of\n" \
    "                   so-far received and transmitted bytes\n"        \
    "    -h host      - D-Link web server hostname (default 192.168.0.1)\n" \
    "    -l           - drop the connection as soon as the number of \"available\"\n" \
    "                   bytes reach zero\n"                             \
    "    -q           - do not write messages to stderr\n"              \
    "    -s           - write messages to system log\n"                 \
    "    pin          - PIN required to unlock the SIM\n"               \
    "    new_pin      - new PIN to be installed in the SIM\n"           \
    "    puk          - PUK required to reset the PIN\n"                \
    "    pid_file     - file to store monitor's PID\n"                  \
    "    account_file - file to store the number of received and transmitted bytes\n" \
    "    storage      - me: read from D-Link device storage\n"          \
    "                   sim: read from SIM storage\n"                   \
    "    box          - inbox: read received messages\n"                \
    "                   outbox: read outgoing (draft) messages\n"       \
    "    msisdn       - phone number of the message recipient\n"        \
    "    text         - UTF-8 encoded message text\n"                   \
    "    index        - index of the message to be deleted -- this is the value\n" \
    "                   of the first field returned by the \"sms list\" command\n" \
    "\n"                                                                \
    "  NOTE: \"sms store\" store messages into the outbox.\n"           \
    "\n"                                                                \
    "  exit codes:\n"                                                   \
    "    1 - invalid argument\n"                                        \
    "    2 - device not ready\n"                                        \
    "    3 - command failed\n"                                          \
    "    4 - no SIM\n"                                                  \
    "    5 - PIN locked SIM\n"                                          \
    "    6 - PUK locked SIM\n"                                          \
    "    7 - unexpected disconnection\n"                                \
    "    8 - unexpectedly connected\n"                                  \
    "\n"                                                                \
    "Report bugs to " PACKAGE_BUGREPORT "\n"                            \
    "            or " PACKAGE_URL "\n"

#ifdef USE_LIBCURL
#define REQUIRED_LIBCURL_VERSION 0x071100 /* 7.17.0 */

#define QCMAP_SCHEME "http"
#define QCMAP_PORT "80"

#define HTTP_CONNECT_TIMEOUT 10000L /* ms */
#define HTTP_TRANSFER_TIMEOUT 30000L /* ms */
#endif

#ifdef USE_FETCH
#define QCMAP_SCHEME SCHEME_HTTP
#define QCMAP_PORT 80

#define HTTP_TRANSFER_TIMEOUT 30 /* seconds */
#endif

#define QCMAP_DEFAULT_HOST "192.168.0.1"
#define QCMAP_PATH "/cgi-bin/qcmap_web_cgi"
#define QCMAP_CONTENT_TYPE "application/json"

#define HTTP_RESPONSE_MAXIMUM_SIZE (64 * 1024)

#define GET_WAN_STATUS "Page=GetWanStatus"      \
    "&mask=2"
#define GET_WAN_STATUS_SIM_STATUS "sim_status"
#define GET_WAN_STATUS_ICCID "iccid"
#define GET_WAN_STATUS_CALL_STATUS "call_status"

#define DO_UNLOCK_PIN "Page=do_unlock_pin"      \
    "&lockpin=%s"
#define DO_UNLOCK_PIN_PUK "Page=do_unlock_pin"  \
    "&lockpin=%s"                               \
    "&lockpuk=%s"
#define DO_UNLOCK_PIN_RESULT "do_result"

#define SET_WWAN_IPV4 "Page=SetWWANIPV4"        \
    "&mask=3"                                   \
    "&enable=1"                                 \
    "&enable_result=0"                          \
    "&backhaul=%d"                              \
    "&backhaul_result=0"                        \
    "&tech_result=0"                            \
    "&tech_pref=0"                              \
    "&profile_id_3gpp=0"                        \
    "&profile_id_3gpp2=0"
#define SET_WWAN_IPV4_BACKHAUL "backhaul"
#define SET_WWAN_IPV4_BACKHAUL_RESULT "backhaul_result"

#define GET_WWAN_STATS "Page=GetWWANSTATS"      \
    "&resetwwwanstats=%d"                       \
    "&family=%d"
#define GET_WWAN_STATS_RX "Bytes_Rx"
#define GET_WWAN_STATS_TX "Bytes_Tx"
#define GET_WWAN_STATS_BACKHAUL "backhaul"
#define GET_WWAN_STATS_BACKHAUL_RESULT "backhaul_result"
#define GET_WWAN_STATS_DNS_1 "Primary_DNS"
#define GET_WWAN_STATS_DNS_2 "Secondary_DNS"

#define SMS_READ "Page=sms_read"                \
    "&storage=%d"                               \
    "&box_flag=%d"
#define SMS_READ_RESULT "result"
#define SMS_READ_ENTRY "entries"
#define SMS_READ_ENTRY_TYPE "sms_type"
#define SMS_READ_ENTRY_INDEX "sms_index"
#define SMS_READ_ENTRY_MSISDN "phone_number"
#define SMS_READ_ENTRY_TEXT "sms_content"
#define SMS_READ_ENTRY_TIME "sms_time"

#define GET_SMS_STORAGE_TYPE "Page=get_sms_storage_type"        \
    "&mask=0"
#define GET_SMS_STORAGE_TYPE_RESULT "result"
#define GET_SMS_STORAGE_TYPE_STORAGE_TYPE "storage_type"

#define SET_SMS_STORAGE_TYPE "Page=set_sms_storage_type"        \
    "&storage_type=%d"
#define SET_SMS_STORAGE_TYPE_RESULT "result"

#define SMS_SAVE "Page=sms_save"                \
    "&msgFlag=%d"                               \
    "&msgLength=%zu"                            \
    "&msgNumber=%s"                             \
    "&token=dummy"                              \
    "&msgContent=%s"
#define SMS_SAVE_RESULT "result"
#define SMS_SAVE_MSG_SUCCESS "msgSuccess"
#define SMS_SAVE_MSG_FAILED "msgFailed"

#define SMS_DELETE "Page=sms_delete"            \
    "&storage=%d"                               \
    "&box_flag=%d"                              \
    "&sms_del=%d"
#define SMS_DELETE_RESULT "result"

#define SMS_TYPE_0_MAX_LENGTH 1000
#define SMS_TYPE_1_MAX_LENGTH 500

#define STATISTICS_POLL_RATE_MINIMUM 10000LL /* ms */
#define STATISTICS_POLL_RATE_MAXIMUM 500LL /* ms */

#define CONSUMED_DATA(a,b) ((a) + (b))

#define SYSLOG_FACILITY LOG_DAEMON

#define PID_FILE_MODE 0600

#define EXIT_CODE_SUCCESS 0
#define EXIT_CODE_INVALID_ARGUMENT 1
#define EXIT_CODE_DEVICE_NOT_READY 2
#define EXIT_CODE_COMMAND_FAILED 3
#define EXIT_CODE_NO_SIM 4
#define EXIT_CODE_PIN_LOCKED_SIM 5
#define EXIT_CODE_PUK_LOCKED_SIM 6
#define EXIT_CODE_UNEXPECTED_DISCONNECTION 7
#define EXIT_CODE_UNEXPECTEDLY_CONNECTED 8


enum error_code {
    ERROR_CODE_SUCCESS = 0,
#ifdef USE_LIBCURL
    ERROR_CODE_LIBCURL_GLOBAL_INIT,
    ERROR_CODE_LIBCURL_OLD,
    ERROR_CODE_LIBCURL_EASY_INIT,
    ERROR_CODE_LIBCURL,
    ERROR_CODE_LIBCURL_URL,
#endif
#ifdef USE_FETCH
    ERROR_CODE_FETCH,
    ERROR_CODE_HTTP_RESPONSE_READING,
#endif
    ERROR_CODE_MEMORY,
    ERROR_CODE_SNPRINTF,
    ERROR_CODE_SMALL_BUFFER,
    ERROR_CODE_HTTP_RESPONSE_TOO_BIG,
    ERROR_CODE_HTTP_RESPONSE_NOT_A_JSON,
    ERROR_CODE_SIM_STATUS_MISSING,
    ERROR_CODE_SIM_STATUS_INVALID,
    ERROR_CODE_SIM_STATUS_UNKNOWN,
    ERROR_CODE_RESULT_MISSING,
    ERROR_CODE_RESULT_INVALID,
    ERROR_CODE_BACKHAUL_MISSING,
    ERROR_CODE_BACKHAUL_INVALID,
    ERROR_CODE_BACKHAUL_RESULT_MISSING,
    ERROR_CODE_BACKHAUL_RESULT_INVALID,
    ERROR_CODE_CALL_STATUS_MISSING,
    ERROR_CODE_CALL_STATUS_UNKNOWN,
    ERROR_CODE_BYTE_RX_MISSING,
    ERROR_CODE_BYTE_RX_INVALID,
    ERROR_CODE_BYTE_TX_MISSING,
    ERROR_CODE_BYTE_TX_INVALID,
    ERROR_CODE_NO_SIM,
    ERROR_CODE_PIN_LOCKED_SIM,
    ERROR_CODE_PUK_LOCKED_SIM,
    ERROR_CODE_WRONG_PIN,
    ERROR_CODE_WRONG_PUK,
    ERROR_CODE_DEVICE_NOT_READY,
    ERROR_CODE_PID_FILE_OPEN,
    ERROR_CODE_PID_FILE_WRITE,
    ERROR_CODE_PID_FILE_CLOSE,
    ERROR_CODE_PID_FILE_REMOVE,
    ERROR_CODE_SIGNAL_HANDLER,
    ERROR_CODE_SLEEP,
    ERROR_CODE_KILL,
    ERROR_CODE_DAEMON,
    ERROR_CODE_DISCONNECTION,
    ERROR_CODE_CONNECTED,
    ERROR_CODE_ACCOUNT_FILE_OPEN,
    ERROR_CODE_ACCOUNT_FILE_WRITE,
    ERROR_CODE_ACCOUNT_FILE_SEEK,
    ERROR_CODE_ACCOUNT_FILE_CLOSE,
    ERROR_CODE_ACCOUNT_FILE_UNLINK,
    ERROR_CODE_ENTRIES_MISSING,
    ERROR_CODE_ENTRIES_INVALID,
    ERROR_CODE_ENTRY_TYPE_MISSING,
    ERROR_CODE_ENTRY_TYPE_INVALID,
    ERROR_CODE_ENTRY_INDEX_MISSING,
    ERROR_CODE_ENTRY_INDEX_INVALID,
    ERROR_CODE_ENTRY_MSISDN_MISSING,
    ERROR_CODE_ENTRY_TEXT_MISSING,
    ERROR_CODE_ENTRY_TIME_MISSING,
    ERROR_CODE_MESSAGE_INVALID,
    ERROR_CODE_MESSAGE_TOO_LONG,
    ERROR_CODE_MSG_SUCCESS_MISSING,
    ERROR_CODE_MSG_SUCCESS_INVALID,
    ERROR_CODE_MSG_FAILED_MISSING,
    ERROR_CODE_MSG_FAILED_INVALID,
    ERROR_CODE_STORAGE_TYPE_MISSING,
    ERROR_CODE_STORAGE_TYPE_INVALID
};

enum log_mode {
    LOG_MODE_STDERR = 1,
    LOG_MODE_SYSLOG = 2
};

struct sm {
#define SM_TYPE_READ 0
#define SM_TYPE_UNREAD 1
#define SM_TYPE_SENT 2
#define SM_TYPE_UNSENT 3
    int type;
    int index;
    char *msisdn;
    char *text;
    char *time;
};

struct error {
    enum error_code code;
    int system_error;
    int value;
    char *info;
#ifdef USE_LIBCURL
    CURLcode result;
    CURLUcode uresult;
#endif
};

struct state {
    const char *name;
    const char *host;
    enum log_mode mode;
    struct error error;
#ifdef USE_LIBCURL
    int curl_initialized;
    CURL *handle;
    CURLU *url;
    char error_buffer[CURL_ERROR_SIZE];
#endif
};

#ifdef USE_LIBCURL
struct write_state {
    char buffer[HTTP_RESPONSE_MAXIMUM_SIZE];
    size_t available;
    size_t offset;
    int overflow;
};
#endif


static int stop = 0;


static void
sig_handler(int sn)
{
    stop = 1;
}

static void
error_init(struct state *state)
{
    state->error.code = ERROR_CODE_SUCCESS;
    state->error.system_error = state->error.value = 0;
    state->error.info = NULL;
#ifdef USE_LIBCURL
    state->error.result = CURLE_OK;
#endif
}

static void
error_set(struct state *state, enum error_code code)
{
    if (state->error.code != ERROR_CODE_SUCCESS)
        return;
    state->error.code = code;
    state->error.system_error = errno;
}

static void
error_set_info(struct state *state, enum error_code code, char *info)
{
    if (state->error.code != ERROR_CODE_SUCCESS)
        return;
    state->error.code = code;
    state->error.info = info;
}

static void
error_set_info_dup(struct state *state, enum error_code code, const char *info)
{
    if (state->error.code != ERROR_CODE_SUCCESS)
        return;
    state->error.code = code;
    state->error.info = strdup(info);
}

static void
error_set_value(struct state *state, enum error_code code, int value)
{
    if (state->error.code != ERROR_CODE_SUCCESS)
        return;
    state->error.code = code;
    state->error.value = value;
}

#ifdef USE_LIBCURL
static void
error_set_result(struct state *state, enum error_code code, CURLcode result)
{
    if (state->error.code != ERROR_CODE_SUCCESS)
        return;
    state->error.code = code;
    if (state->error_buffer[0] == '\0') {
        state->error.result = result;
    } else {
        state->error.info = strdup(state->error_buffer);
    }
}

static void
error_set_uresult(struct state *state, enum error_code code, CURLUcode result)
{
    if (state->error.code != ERROR_CODE_SUCCESS)
        return;
    state->error.code = code;
    state->error.uresult = result;
}
#endif

static int
error_check(struct state *state)
{
    return (state->error.code != ERROR_CODE_SUCCESS);
}

static enum error_code
error_fini(struct state *state)
{
    free(state->error.info);
    return state->error.code;
}

static void
error_print(struct state *state)
{
    int type = 0;
    int level = LOG_WARNING;
    const char *msg;
    switch (state->error.code) {
    case ERROR_CODE_SUCCESS:
        level = LOG_INFO;
        msg = "success\n";
        break;
#ifdef USE_LIBCURL
    case ERROR_CODE_LIBCURL_GLOBAL_INIT:
        level = LOG_ERR;
        msg = "libcurl global initialization failed\n";
        break;
    case ERROR_CODE_LIBCURL_OLD:
        level = LOG_ERR;
        msg = "libcurl too old: version 7.17.0 or newer is required\n";
        break;
    case ERROR_CODE_LIBCURL_EASY_INIT:
        level = LOG_ERR;
        msg = "libcurl easy initialization failed\n";
        break;
    case ERROR_CODE_LIBCURL:
        type = 4;
        level = LOG_ERR;
        msg = "libcurl error: %s\n";
        break;
    case ERROR_CODE_LIBCURL_URL:
        type = 5;
        level = LOG_ERR;
        msg = "libcurl url error: %s\n";
        break;
#endif
#ifdef USE_FETCH
    case ERROR_CODE_FETCH:
        type = 1;
        level = LOG_ERR;
        msg = "libfetch error: %s\n";
        break;
    case ERROR_CODE_HTTP_RESPONSE_READING:
        level = LOG_ERR;
        msg = "HTTP stream error\n";
        break;
#endif
    case ERROR_CODE_MEMORY:
        type = 2;
        level = LOG_ERR;
        msg = "could not allocate memory: %s\n";
        break;
    case ERROR_CODE_SNPRINTF:
        type = 2;
        level = LOG_ERR;
        msg = "snprintf function failed: %s\n";
        break;
    case ERROR_CODE_SMALL_BUFFER:
        type = 3;
        level = LOG_ERR;
        msg = "snprintf buffer @%d is too small\n";
        break;
    case ERROR_CODE_HTTP_RESPONSE_TOO_BIG:
        msg = "HTTP response too big\n";
        break;
    case ERROR_CODE_HTTP_RESPONSE_NOT_A_JSON:
        type = 1;
        msg = "HTTP response is not a valid JSON: %s\n";
        break;
    case ERROR_CODE_SIM_STATUS_MISSING:
        msg = "missing SIM status field\n";
        break;
    case ERROR_CODE_SIM_STATUS_INVALID:
        type = 1;
        msg = "invalid SIM status value: %s\n";
        break;
    case ERROR_CODE_SIM_STATUS_UNKNOWN:
        type = 3;
        msg = "unknown SIM status: %d\n";
        break;
    case ERROR_CODE_RESULT_MISSING:
        msg = "missing result field\n";
        break;
    case ERROR_CODE_RESULT_INVALID:
        type = 1;
        msg = "unexpected result value: %s\n";
        break;
    case ERROR_CODE_BACKHAUL_MISSING:
        msg = "missing backhaul field\n";
        break;
    case ERROR_CODE_BACKHAUL_INVALID:
        type = 1;
        msg = "unexpected backhaul value: %s\n";
        break;
    case ERROR_CODE_BACKHAUL_RESULT_MISSING:
        msg = "missing backhaul_result field\n";
        break;
    case ERROR_CODE_BACKHAUL_RESULT_INVALID:
        type = 1;
        msg = "unexpected backhaul_result value: %s\n";
        break;
    case ERROR_CODE_CALL_STATUS_MISSING:
        msg = "missing call status field\n";
        break;
    case ERROR_CODE_CALL_STATUS_UNKNOWN:
        type = 1;
        msg = "unknown call status: %s\n";
        break;
    case ERROR_CODE_BYTE_RX_MISSING:
        msg = "missing byte_rx field\n";
        break;
    case ERROR_CODE_BYTE_RX_INVALID:
        type = 1;
        msg = "invalid byte_rx value: %s\n";
        break;
    case ERROR_CODE_BYTE_TX_MISSING:
        msg = "missing byte_tx field\n";
        break;
    case ERROR_CODE_BYTE_TX_INVALID:
        type = 1;
        msg = "invalid byte_tx value: %s\n";
        break;
    case ERROR_CODE_NO_SIM:
        level = LOG_NOTICE;
        msg = "no SIM\n";
        break;
    case ERROR_CODE_PIN_LOCKED_SIM:
        level = LOG_NOTICE;
        msg = "PIN locked SIM\n";
        break;
    case ERROR_CODE_PUK_LOCKED_SIM:
        level = LOG_NOTICE;
        msg = "PUK locked SIM (?)\n";
        break;
    case ERROR_CODE_WRONG_PIN:
        level = LOG_NOTICE;
        msg = "wrong PIN\n";
        break;
    case ERROR_CODE_WRONG_PUK:
        level = LOG_NOTICE;
        msg = "wrong PUK\n";
        break;
    case ERROR_CODE_DEVICE_NOT_READY:
        type = 1;
        msg = "device not ready: %s\n";
        break;
    case ERROR_CODE_PID_FILE_OPEN:
        type = 2;
        level = LOG_ERR;
        msg = "could not open PID file: %s\n";
        break;
    case ERROR_CODE_PID_FILE_WRITE:
        type = 2;
        level = LOG_ERR;
        msg = "could not write PID file: %s\n";
        break;
    case ERROR_CODE_PID_FILE_CLOSE:
        type = 2;
        level = LOG_ERR;
        msg = "could not close PID file: %s\n";
        break;
    case ERROR_CODE_PID_FILE_REMOVE:
        type = 2;
        level = LOG_ERR;
        msg = "could not remove PID file: %s\n";
        break;
    case ERROR_CODE_SIGNAL_HANDLER:
        type = 2;
        level = LOG_ERR;
        msg = "could not install signal handler: %s\n";
        break;
    case ERROR_CODE_SLEEP:
        type = 2;
        level = LOG_ERR;
        msg = "could not sleep: %s\n";
        break;
    case ERROR_CODE_KILL:
        type = 2;
        level = LOG_ERR;
        msg = "could not send signal to monitor: %s\n";
        break;
    case ERROR_CODE_DAEMON:
        type = 2;
        level = LOG_ERR;
        msg = "could not daemonize monitor: %s\n";
        break;
    case ERROR_CODE_DISCONNECTION:
        level = LOG_NOTICE;
        msg = "unexpected disconnection\n";
        break;
    case ERROR_CODE_CONNECTED:
        level = LOG_NOTICE;
        msg = "unexpectedly connected, disconnected\n";
        break;
    case ERROR_CODE_ACCOUNT_FILE_OPEN:
        type = 2;
        level = LOG_ERR;
        msg = "could not open account file: %s\n";
        break;
    case ERROR_CODE_ACCOUNT_FILE_WRITE:
        type = 2;
        level = LOG_ERR;
        msg = "could not write account file: %s\n";
        break;
    case ERROR_CODE_ACCOUNT_FILE_SEEK:
        type = 2;
        level = LOG_ERR;
        msg = "could not seek account file: %s\n";
        break;
    case ERROR_CODE_ACCOUNT_FILE_CLOSE:
        type = 2;
        level = LOG_ERR;
        msg = "could not close account file: %s\n";
        break;
    case ERROR_CODE_ACCOUNT_FILE_UNLINK:
        type = 2;
        level = LOG_ERR;
        msg = "could not delete account file: %s\n";
        break;
    case ERROR_CODE_ENTRIES_MISSING:
        msg = "missing entries field\n";
        break;
    case ERROR_CODE_ENTRIES_INVALID:
        msg = "entries field does not contain objects\n";
        break;
    case ERROR_CODE_ENTRY_TYPE_MISSING:
        msg = "an entries object is missing sms_type field\n";
        break;
    case ERROR_CODE_ENTRY_TYPE_INVALID:
        type = 1;
        msg = "invalid entries object's sms_type value: %s\n";
        break;
    case ERROR_CODE_ENTRY_INDEX_MISSING:
        msg = "an entries object is missing sms_index field\n";
        break;
    case ERROR_CODE_ENTRY_INDEX_INVALID:
        type = 1;
        msg = "invalid entries object's sms_index value: %s\n";
        break;
    case ERROR_CODE_ENTRY_MSISDN_MISSING:
        msg = "an entries object is missing phone_number field\n";
        break;
    case ERROR_CODE_ENTRY_TEXT_MISSING:
        msg = "an entries object is missing sms_content field\n";
        break;
    case ERROR_CODE_ENTRY_TIME_MISSING:
        msg = "an entries object is missing sms_time field\n";
        break;
    case ERROR_CODE_MESSAGE_INVALID:
        msg = "short-message text is not a valid UTF-8 string\n";
        break;
    case ERROR_CODE_MESSAGE_TOO_LONG:
        type = 3;
        msg = "short-message text is too long (maximum is %d characters)\n";
        break;
    case ERROR_CODE_MSG_SUCCESS_MISSING:
        msg = "missing msgSuccess field\n";
        break;
    case ERROR_CODE_MSG_SUCCESS_INVALID:
        type = 1;
        msg = "invalid msgSuccess value: %s\n";
        break;
    case ERROR_CODE_MSG_FAILED_MISSING:
        msg = "missing msgFailed field\n";
        break;
    case ERROR_CODE_MSG_FAILED_INVALID:
        type = 1;
        msg = "invalid msgFailed value: %s\n";
        break;
    case ERROR_CODE_STORAGE_TYPE_MISSING:
        msg = "missing storage_type field\n";
        break;
    case ERROR_CODE_STORAGE_TYPE_INVALID:
        type = 1;
        msg = "invalid storage_type value: %s\n";
        break;
    default:
        msg = "undefined error!\n";
    }
    if (state->mode & LOG_MODE_STDERR) {
        if (state->name != NULL)
            fprintf(stderr, "%s: ", state->name);
        switch (type) {
        case 0:
            fprintf(stderr, "%s", msg);
            break;
        case 1:
            fprintf(stderr, msg, state->error.info);
            break;
        case 2:
            fprintf(stderr, msg, strerror(state->error.system_error));
            break;
#ifdef USE_LIBCURL
        case 4:
            if (state->error.info == NULL) {
                fprintf(stderr, msg, curl_easy_strerror(state->error.result));
                break;
            }
            fprintf(stderr, msg, state->error.info);
            break;
        case 5:
            fprintf(stderr, msg, curl_url_strerror(state->error.uresult));
            break;
#endif
        default: /* 3 */
            fprintf(stderr, msg, state->error.value);
        }
    }
#ifdef HAVE_SYSLOG_H
    if (state->mode & LOG_MODE_SYSLOG) {
        switch (type) {
        case 0:
            syslog(level | SYSLOG_FACILITY, "%s", msg);
            break;
        case 1:
            syslog(level | SYSLOG_FACILITY, msg, state->error.info);
            break;
        case 2:
            syslog(level | SYSLOG_FACILITY, msg,
                   strerror(state->error.system_error));
            break;
#ifdef USE_LIBCURL
        case 4:
            if (state->error.info == NULL) {
                syslog(level | SYSLOG_FACILITY, msg,
                       curl_easy_strerror(state->error.result));
                break;
            }
            syslog(level | SYSLOG_FACILITY, msg, state->error.info);
            break;
        case 5:
            syslog(level | SYSLOG_FACILITY, msg,
                   curl_url_strerror(state->error.uresult));
            break;
#endif
        default: /* 3 */
            syslog(level | SYSLOG_FACILITY, msg, state->error.value);
        }
#endif
    }
}

static int
error_to_exit_code(struct state *state)
{
    switch (state->error.code) {
    case ERROR_CODE_SUCCESS:
        return EXIT_CODE_SUCCESS;
    case ERROR_CODE_NO_SIM:
        return EXIT_CODE_NO_SIM;
    case ERROR_CODE_PIN_LOCKED_SIM:
        return EXIT_CODE_PIN_LOCKED_SIM;
    case ERROR_CODE_PUK_LOCKED_SIM:
        return EXIT_CODE_PUK_LOCKED_SIM;
    case ERROR_CODE_DEVICE_NOT_READY:
        return EXIT_CODE_DEVICE_NOT_READY;
    case ERROR_CODE_DISCONNECTION:
        return EXIT_CODE_UNEXPECTED_DISCONNECTION;
    case ERROR_CODE_CONNECTED:
        return EXIT_CODE_UNEXPECTEDLY_CONNECTED;
    default:
        return EXIT_CODE_COMMAND_FAILED;
    }
}

static void
log_print(struct state *state, int level, const char *message, ...)
{
    va_list margs;
    if (state->mode & LOG_MODE_STDERR) {
        if (state->name != NULL)
            fprintf(stderr, "%s: ", state->name);
        va_start(margs, message);
        vfprintf(stderr, message, margs);
        va_end(margs);
    }
#ifdef HAVE_SYSLOG_H
    if (state->mode & LOG_MODE_SYSLOG) {
        va_start(margs, message);
        vsyslog(level | SYSLOG_FACILITY, message, margs);
        va_end(margs);
    }
#endif
}

#ifdef USE_LIBCURL
size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t rv;
    struct write_state *state = (struct write_state *)userdata;
    rv = size * nmemb;
    if (state->overflow)
        return rv;
    if (rv > state->available) {
        state->overflow = 1;
        return rv;
    }
    memcpy(&state->buffer[state->offset], ptr, rv);
    state->available -= rv;
    state->offset += rv;
    return rv;
}

static cJSON *
qcmap_post(struct state *state, const char *request, int length)
{
    cJSON *response;
    const cJSON *commit;
    CURLcode result;
    struct write_state *wstate;
    if (!state->curl_initialized) {
        curl_version_info_data *data;
        if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
            error_set(state, ERROR_CODE_LIBCURL_GLOBAL_INIT);
            return NULL;
        }
        state->curl_initialized = 1;
        data = curl_version_info(CURLVERSION_NOW);
        if (data->version_num < REQUIRED_LIBCURL_VERSION) {
            error_set(state, ERROR_CODE_LIBCURL_OLD);
            return NULL;
        }
    }
    if (state->url == NULL) {
        CURLUcode uresult;
        state->url = curl_url();
        if (state->url == NULL) {
            error_set(state, ERROR_CODE_MEMORY);
            return NULL;
        }
        uresult = curl_url_set(state->url, CURLUPART_SCHEME, QCMAP_SCHEME, 0);
        if (uresult == CURLUE_OK)
            uresult = curl_url_set(state->url, CURLUPART_HOST, state->host, 0);
        if (uresult == CURLUE_OK)
            uresult = curl_url_set(state->url, CURLUPART_PORT, QCMAP_PORT, 0);
        if (uresult == CURLUE_OK)
            uresult = curl_url_set(state->url, CURLUPART_PATH, QCMAP_PATH, 0);
        if (uresult != CURLUE_OK) {
            error_set_uresult(state, ERROR_CODE_LIBCURL_URL, uresult);
            return NULL;
        }
    }
    if (state->handle == NULL) {
        state->handle = curl_easy_init();
        if (state->handle == NULL) {
            error_set(state, ERROR_CODE_LIBCURL_EASY_INIT);
            return NULL;
        }
        result = curl_easy_setopt(state->handle, CURLOPT_ERRORBUFFER,
                                  state->error_buffer);
        if (result == CURLE_OK)
            result = curl_easy_setopt(state->handle, CURLOPT_CURLU, state->url);
        if (result == CURLE_OK)
            result = curl_easy_setopt(state->handle, CURLOPT_WRITEFUNCTION,
                                      write_callback);
        if (result == CURLE_OK)
            result = curl_easy_setopt(state->handle, CURLOPT_POST, 1L);
        if (result == CURLE_OK)
            result = curl_easy_setopt(state->handle, CURLOPT_CONNECTTIMEOUT_MS,
                                      HTTP_CONNECT_TIMEOUT);
        if (result == CURLE_OK)
            result = curl_easy_setopt(state->handle, CURLOPT_TIMEOUT_MS,
                                      HTTP_TRANSFER_TIMEOUT);
        if (result != CURLE_OK) {
            error_set_result(state, ERROR_CODE_LIBCURL, result);
            return NULL;
        }
    }
    wstate = (struct write_state *)malloc(sizeof(struct write_state));
    if (wstate == NULL) {
        error_set(state, ERROR_CODE_MEMORY);
        return NULL;
    }
    wstate->available = sizeof(wstate->buffer);
    wstate->offset = 0;
    wstate->overflow = 0;
    result = curl_easy_setopt(state->handle, CURLOPT_WRITEDATA, wstate);
    if (result == CURLE_OK)
        result = curl_easy_setopt(state->handle, CURLOPT_POSTFIELDS, request);
    if (result == CURLE_OK)
        result = curl_easy_setopt(state->handle, CURLOPT_POSTFIELDSIZE,
                                  (long)length);
    if (result == CURLE_OK) {
        state->error_buffer[0] = '\0';
        result = curl_easy_perform(state->handle);
    }
    if (result != CURLE_OK) {
        error_set_result(state, ERROR_CODE_LIBCURL, result);
        goto error1;
    }
    if (wstate->overflow) {
        error_set(state, ERROR_CODE_HTTP_RESPONSE_TOO_BIG);
        goto error1;
    }
    response = cJSON_ParseWithLength(wstate->buffer, wstate->offset);
    if (response == NULL) {
        wstate->buffer[wstate->offset] = '\0';
        error_set_info_dup(state, ERROR_CODE_HTTP_RESPONSE_NOT_A_JSON,
                           wstate->buffer);
        free(wstate);
        return NULL;
    }
    free(wstate);
    commit = cJSON_GetObjectItemCaseSensitive(response, "commit");
    if (cJSON_IsString(commit) && (commit->valuestring != NULL)) {
        error_set_info_dup(state, ERROR_CODE_DEVICE_NOT_READY,
                           commit->valuestring);
        cJSON_free(response);
        return NULL;
    }
    return response;

error1:
    free(wstate);
    return NULL;
}
#endif

#ifdef USE_FETCH
static cJSON *
qcmap_post(struct state *state, const char *request, int length)
{
    char *buffer;
    FILE *stream;
    cJSON *response;
    const cJSON *commit;
    size_t offset;
    struct url *qcmap_url;
    buffer = (char *)malloc(HTTP_RESPONSE_MAXIMUM_SIZE * sizeof(char));
    if (buffer == NULL) {
        error_set(state, ERROR_CODE_MEMORY);
        return NULL;
    }
    qcmap_url = fetchMakeURL(QCMAP_SCHEME, state->host, QCMAP_PORT,
                             QCMAP_PATH, NULL, NULL);
    if (qcmap_url == NULL) {
        error_set_info_dup(state, ERROR_CODE_FETCH, fetchLastErrString);
        goto error1;
    }
    stream = fetchReqHTTP(qcmap_url, "POST", NULL, QCMAP_CONTENT_TYPE, request);
    if (stream == NULL) {
        error_set_info_dup(state, ERROR_CODE_FETCH, fetchLastErrString);
        goto error2;
    }
    for (offset = 0; offset < HTTP_RESPONSE_MAXIMUM_SIZE;) {
        offset += fread(&buffer[offset], sizeof(char),
                        HTTP_RESPONSE_MAXIMUM_SIZE - offset, stream);
        if (ferror(stream)) {
            error_set(state, ERROR_CODE_HTTP_RESPONSE_READING);
            goto error3;
        }
        if (feof(stream))
            break;
    }
    if (offset >= HTTP_RESPONSE_MAXIMUM_SIZE) {
        error_set(state, ERROR_CODE_HTTP_RESPONSE_TOO_BIG);
        goto error3;
    }
    if (fclose(stream) != 0) {
        error_set(state, ERROR_CODE_HTTP_RESPONSE_READING);
        goto error2;
    }
    fetchFreeURL(qcmap_url);
    offset *= sizeof(char);
    response = cJSON_ParseWithLength(buffer, offset);
    if (response == NULL) {
        error_set_info(state, ERROR_CODE_HTTP_RESPONSE_NOT_A_JSON, buffer);
        return NULL;
    }
    free(buffer);
    commit = cJSON_GetObjectItemCaseSensitive(response, "commit");
    if (cJSON_IsString(commit) && (commit->valuestring != NULL)) {
        error_set_info_dup(state, ERROR_CODE_DEVICE_NOT_READY,
                           commit->valuestring);
        cJSON_free(response);
        return NULL;
    }
    return response;

error3:
    fclose(stream);

error2:
    fetchFreeURL(qcmap_url);

error1:
    free(buffer);
    return NULL;
}
#endif

static void
get_status(struct state *state, int *sim_status,
           char **iccid, char **call_status)
{
    cJSON *status;
    const cJSON *jsim_status, *jiccid, *jcall_status;
    status = qcmap_post(state, GET_WAN_STATUS, sizeof(GET_WAN_STATUS) - 1);
    if (status == NULL)
        return;
    if (sim_status != NULL) {
        jsim_status =
            cJSON_GetObjectItemCaseSensitive(status, GET_WAN_STATUS_SIM_STATUS);
        if (!cJSON_IsString(jsim_status) ||
            (jsim_status->valuestring == NULL)) {
            error_set(state, ERROR_CODE_SIM_STATUS_MISSING);
            goto error1;
        }
        errno = 0;
        *sim_status = (int)strtol(jsim_status->valuestring, NULL, 10);
        if (errno != 0) {
            error_set_info_dup(state, ERROR_CODE_SIM_STATUS_INVALID,
                               jsim_status->valuestring);
            goto error1;
        }
    }
    if (iccid != NULL) {
        jiccid = cJSON_GetObjectItemCaseSensitive(status, GET_WAN_STATUS_ICCID);
        if (!cJSON_IsString(jiccid) || (jiccid->valuestring == NULL)) {
            *iccid = NULL;
        } else {
            *iccid = strdup(jiccid->valuestring);
        }
    }
    if (call_status != NULL) {
        jcall_status =
            cJSON_GetObjectItemCaseSensitive(status,
                                             GET_WAN_STATUS_CALL_STATUS);
        if (!cJSON_IsString(jcall_status) ||
            (jcall_status->valuestring == NULL)) {
            if (iccid != NULL)
                free(*iccid);
            error_set(state, ERROR_CODE_CALL_STATUS_MISSING);
            goto error1;
        }
        *call_status = strdup(jcall_status->valuestring);
    }

error1:
    cJSON_free(status);
}

static void
do_unlock_sim(struct state *state, const char *pin)
{
    int n;
    char buffer[sizeof(DO_UNLOCK_PIN)+8];
    cJSON *response;
    const cJSON *result;
    n = snprintf(buffer, sizeof(buffer), DO_UNLOCK_PIN, pin);
    if (n < 0) {
        error_set(state, ERROR_CODE_SNPRINTF);
        return;
    }
    if (n >= sizeof(buffer)) {
        error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
        return;
    }
    response = qcmap_post(state, buffer, n);
    if (response == NULL)
        return;
    result = cJSON_GetObjectItemCaseSensitive(response, DO_UNLOCK_PIN_RESULT);
    if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(result->valuestring, "FAILD") == 0) {
        error_set(state, ERROR_CODE_WRONG_PIN);
    } else if (strcmp(result->valuestring, "SUCCESS") != 0) {
        error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                           result->valuestring);
    }

error1:
    cJSON_free(response);
}

/*
 * !!! NOT TESTED !!!
 */
static void
do_reset_pin(struct state *state, const char *new_pin, const char *puk)
{
    int n;
    char buffer[sizeof(DO_UNLOCK_PIN_PUK)+24];
    cJSON *response;
    const cJSON *result;
    n = snprintf(buffer, sizeof(buffer), DO_UNLOCK_PIN_PUK, new_pin, puk);
    if (n < 0) {
        error_set(state, ERROR_CODE_SNPRINTF);
        return;
    }
    if (n >= sizeof(buffer)) {
        error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
        return;
    }
    response = qcmap_post(state, buffer, n);
    if (response == NULL)
        return;
    result = cJSON_GetObjectItemCaseSensitive(response, DO_UNLOCK_PIN_RESULT);
    if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(result->valuestring, "FAILD") == 0) {
        error_set(state, ERROR_CODE_WRONG_PUK);
    } else if (strcmp(result->valuestring, "SUCCESS") != 0) {
        error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                           result->valuestring);
    }

error1:
    cJSON_free(response);
}

static void
dl_connect(struct state *state, int enable)
{
    int n;
    char buffer[sizeof(SET_WWAN_IPV4)];
    cJSON *response;
    const cJSON *backhaul, *backhaul_result;
    n = snprintf(buffer, sizeof(buffer), SET_WWAN_IPV4, enable);
    if (n < 0) {
        error_set(state, ERROR_CODE_SNPRINTF);
        return;
    }
    if (n >= sizeof(buffer)) {
        error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
        return;
    }
    response = qcmap_post(state, buffer, n);
    if (response == NULL)
        return;
    backhaul_result =
        cJSON_GetObjectItemCaseSensitive(response,
                                         SET_WWAN_IPV4_BACKHAUL_RESULT);
    if (!cJSON_IsString(backhaul_result) ||
        (backhaul_result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_BACKHAUL_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(backhaul_result->valuestring, "SUCCESS") != 0) {
        error_set_info_dup(state, ERROR_CODE_BACKHAUL_RESULT_INVALID,
                           backhaul_result->valuestring);
        goto error1;
    }
    backhaul = cJSON_GetObjectItemCaseSensitive(response,
                                                SET_WWAN_IPV4_BACKHAUL);
    if (!cJSON_IsString(backhaul) || (backhaul->valuestring == NULL)) {
        error_set(state, ERROR_CODE_BACKHAUL_MISSING);
        goto error1;
    }
    if (enable) {
        if (strcmp(backhaul->valuestring, "connected") != 0)
            error_set_info_dup(state, ERROR_CODE_BACKHAUL_INVALID,
                               backhaul->valuestring);
    } else {
        if (strcmp(backhaul->valuestring, "disconnected") != 0)
            error_set_info_dup(state, ERROR_CODE_BACKHAUL_INVALID,
                               backhaul->valuestring);
    }

error1:
    cJSON_free(response);
}

static void
get_statistics(struct state *state, int reset, int family,
               int *connected, long long *rx, long long *tx,
               char **first_dns, char **second_dns)
{
    int n;
    char buffer[sizeof(GET_WWAN_STATS)];
    cJSON *response;
    const cJSON *backhaul, *backhaul_result, *jrx, *jtx, *jdns;
    n = snprintf(buffer, sizeof(buffer), GET_WWAN_STATS, reset, family);
    if (n < 0) {
        error_set(state, ERROR_CODE_SNPRINTF);
        return;
    }
    if (n >= sizeof(buffer)) {
        error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
        return;
    }
    response = qcmap_post(state, buffer, n);
    if (response == NULL)
        return;
    backhaul_result =
        cJSON_GetObjectItemCaseSensitive(response,
                                         GET_WWAN_STATS_BACKHAUL_RESULT);
    if (!cJSON_IsString(backhaul_result) ||
        (backhaul_result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_BACKHAUL_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(backhaul_result->valuestring, "SUCCESS") != 0) {
        error_set_info_dup(state, ERROR_CODE_BACKHAUL_RESULT_INVALID,
                           backhaul_result->valuestring);
        goto error1;
    }
    if (connected != NULL) {
        backhaul =
            cJSON_GetObjectItemCaseSensitive(response, GET_WWAN_STATS_BACKHAUL);
        if (!cJSON_IsString(backhaul) || (backhaul->valuestring == NULL)) {
            error_set(state, ERROR_CODE_BACKHAUL_MISSING);
            goto error1;
        }
        if (strcmp(backhaul->valuestring, "connected") == 0) {
            *connected = 1;
        } else if (strcmp(backhaul->valuestring, "disconnected") == 0) {
            *connected = 0;
        } else {
            error_set_info_dup(state, ERROR_CODE_BACKHAUL_INVALID,
                               backhaul->valuestring);
        }
    }
    if (rx != NULL) {
        jrx = cJSON_GetObjectItemCaseSensitive(response, GET_WWAN_STATS_RX);
        if (!cJSON_IsString(jrx) || (jrx->valuestring == NULL)) {
            error_set(state, ERROR_CODE_BYTE_RX_MISSING);
            goto error1;
        }
        errno = 0;
        *rx = strtoll(jrx->valuestring, NULL, 10);
        if (errno != 0) {
            error_set_info_dup(state, ERROR_CODE_BYTE_RX_INVALID,
                               jrx->valuestring);
            goto error1;
        }
    }
    if (tx != NULL) {
        jtx = cJSON_GetObjectItemCaseSensitive(response, GET_WWAN_STATS_TX);
        if (!cJSON_IsString(jtx) || (jtx->valuestring == NULL)) {
            error_set(state, ERROR_CODE_BYTE_TX_MISSING);
            goto error1;
        }
        errno = 0;
        *tx = strtoll(jtx->valuestring, NULL, 10);
        if (errno != 0) {
            error_set_info_dup(state, ERROR_CODE_BYTE_TX_INVALID,
                               jtx->valuestring);
            goto error1;
        }
    }
    if (first_dns != NULL) {
        jdns = cJSON_GetObjectItemCaseSensitive(response, GET_WWAN_STATS_DNS_1);
        if (!cJSON_IsString(jdns) || (jdns->valuestring == NULL)) {
            *first_dns = NULL;
        } else {
            *first_dns = strdup(jdns->valuestring);
        }
    }
    if (second_dns != NULL) {
        jdns = cJSON_GetObjectItemCaseSensitive(response, GET_WWAN_STATS_DNS_2);
        if (!cJSON_IsString(jdns) || (jdns->valuestring == NULL)) {
            *second_dns = NULL;
        } else {
            *second_dns = strdup(jdns->valuestring);
        }
    }

error1:
    cJSON_free(response);
}

static char *
get_iccid(struct state *state)
{
    int sim_status;
    char *iccid;
    get_status(state, &sim_status, &iccid, NULL);
    if (error_check(state))
        return NULL;
    switch (sim_status) {
    case 1:
        free(iccid);
        error_set(state, ERROR_CODE_NO_SIM);
        return NULL;
    case 2: case 3: case 4:
        break;
    default:
        error_set_value(state, ERROR_CODE_SIM_STATUS_UNKNOWN, sim_status);
    }
    return iccid;
}

static void
unlock_sim(struct state *state, const char *pin)
{
    int sim_status;
    get_status(state, &sim_status, NULL, NULL);
    if (error_check(state))
        return;
    switch (sim_status) {
    case 1:
        error_set(state, ERROR_CODE_NO_SIM);
        break;
    case 2:
        do_unlock_sim(state, pin);
        break;
    case 3:
        error_set(state, ERROR_CODE_PUK_LOCKED_SIM);
    case 4:
        break;
    default:
        error_set_value(state, ERROR_CODE_SIM_STATUS_UNKNOWN, sim_status);
    }
}

/*
 * !!! NOT TESTED !!!
 */
static void
reset_pin(struct state *state, const char *new_pin, const char *puk)
{
    int sim_status;
    get_status(state, &sim_status, NULL, NULL);
    if (error_check(state))
        return;
    switch (sim_status) {
    case 1:
        error_set(state, ERROR_CODE_NO_SIM);
        break;
    case 2:
        error_set(state, ERROR_CODE_PIN_LOCKED_SIM);
        break;
    case 3:
        do_reset_pin(state, new_pin, puk);
    case 4:
        break;
    default:
        error_set_value(state, ERROR_CODE_SIM_STATUS_UNKNOWN, sim_status);
    }
}

static int
run_daemon(struct state *state, struct pidfh *pid_file, FILE *account_file)
{
    int connected;
    long long rx0, rx1, rx2, tx0, tx1, tx2;
    struct timespec wt1, wt2;
    get_statistics(state, 0, 4, NULL, &rx0, &tx0, NULL, NULL);
    if (error_check(state))
        return 0;
    rx1 = tx1 = 0LL;
    wt1.tv_sec = (time_t)(STATISTICS_POLL_RATE_MINIMUM / 1000LL);
    wt1.tv_nsec = (long)((STATISTICS_POLL_RATE_MINIMUM % 1000LL) * 1000000LL);
    while (!stop) {
        wt2 = wt1;
        while ((!stop) && (nanosleep(&wt2, &wt2) == -1))
            if (errno != EINTR) {
                error_set(state, ERROR_CODE_SLEEP);
                return 0;
            }
        get_statistics(state, 0, 4, &connected, &rx2, &tx2, NULL, NULL);
        if (error_check(state))
            return 0;
        rx2 -= rx0;
        tx2 -= tx0;
        if (!connected) {
            error_set(state, ERROR_CODE_DISCONNECTION);
            return 1;
        }
        if ((rx2 != rx1) || (tx2 != tx1)) {
            log_print(state, LOG_INFO, "rx: %lld B, tx: %lld B\n", rx2, tx2);
            if (fprintf(account_file, "%lld %lld\n", rx2, tx2) < 0) {
                error_set(state, ERROR_CODE_ACCOUNT_FILE_WRITE);
                return 0;
            }
            if (fseek(account_file, 0L, SEEK_SET) == -1) {
                error_set(state, ERROR_CODE_ACCOUNT_FILE_SEEK);
                return 0;
            }
        }
        rx1 = rx2;
        tx1 = tx2;
    }
    return 0;
}

static int
run_daemon_capped(struct state *state, struct pidfh *pid_file,
                  FILE *account_file, long long cap, int enforce_cap)
{
    int connected;
    long long rate, throughput, tmp;
    long long consumed1, consumed2, rx0, tx0, rx2, tx2;
    struct timespec wt1, wt2;
    get_statistics(state, 0, 4, NULL, &rx0, &tx0, NULL, NULL);
    if (error_check(state))
        return 0;
    consumed1 = throughput = 0LL;
    rate = STATISTICS_POLL_RATE_MINIMUM;
    wt1.tv_sec = (time_t)(rate / 1000LL);
    wt1.tv_nsec = (long)((rate % 1000LL) * 1000000LL);
    while (!stop) {
        wt2 = wt1;
        while ((!stop) && (nanosleep(&wt2, &wt2) == -1))
            if (errno != EINTR) {
                error_set(state, ERROR_CODE_SLEEP);
                return 0;
            }
        get_statistics(state, 0, 4, &connected, &rx2, &tx2, NULL, NULL);
        if (error_check(state))
            return 0;
        rx2 -= rx0;
        tx2 -= tx0;
        if (!connected) {
            error_set(state, ERROR_CODE_DISCONNECTION);
            return 1;
        }
        consumed2 = CONSUMED_DATA(rx2, tx2);
        if (consumed2 != consumed1) {
            log_print(state, LOG_INFO, "remaining: %lld B @%lld B/s (max)\n",
                      cap - consumed2, throughput);
            if (fprintf(account_file, "%lld %lld\n", rx2, tx2) < 0) {
                error_set(state, ERROR_CODE_ACCOUNT_FILE_WRITE);
                return 0;
            }
            if (fseek(account_file, 0L, SEEK_SET) == -1) {
                error_set(state, ERROR_CODE_ACCOUNT_FILE_SEEK);
                return 0;
            }
        }
        if (enforce_cap && (consumed2 >= cap)) {
            log_print(state, LOG_INFO, "cap reached\n");
            return 0;
        }
        /*
         * Compute current throughput and keep the highest value measured.
         */
        tmp = consumed2 - consumed1;
        tmp *= 1000LL;
        tmp /= rate; /* B/s */
        if (throughput < tmp)
            throughput = tmp;
        /* 
         * Compute the time needed (in ms) to reach half the distance to cap
         * at the maximum measured throughput.
         */
        if (throughput < 1LL) {
            rate = STATISTICS_POLL_RATE_MINIMUM;
        } else {
            rate = cap - consumed2;
            rate *= 500LL;
            rate /= throughput; /* ms */
            if (rate > STATISTICS_POLL_RATE_MINIMUM) {
                rate = STATISTICS_POLL_RATE_MINIMUM;
            } else if (rate < STATISTICS_POLL_RATE_MAXIMUM) {
                rate = STATISTICS_POLL_RATE_MAXIMUM;
            }
        }
        wt1.tv_sec = (time_t)(rate / 1000LL);
        wt1.tv_nsec = (long)((rate % 1000LL) * 1000000LL);
        consumed1 = consumed2;
    }
    return 0;
}

static void
start_monitor(struct state *state, const char *pid_filename,
              const char *account_filename, long long cap, int enforce_cap)
{
    int delete_account_file, do_connect, sim_status;
    char *call_status;
    FILE *account_file;
    pid_t pid;
    struct pidfh *pid_file;
    struct sigaction saction;
    pid_file = pidfile_open(pid_filename, 0600, &pid);
    if (pid_file == NULL) {
        if (errno != EEXIST) {
            error_set(state, ERROR_CODE_PID_FILE_OPEN);
            return;
        }
        log_print(state, LOG_INFO, "monitor already running (PID %d)\n", pid);
        return;
    }
    saction.sa_handler = sig_handler;
    saction.sa_flags = 0;
    sigemptyset(&saction.sa_mask);
    if (sigaction(SIGTERM, &saction, NULL) == -1) {
        error_set(state, ERROR_CODE_SIGNAL_HANDLER);
        goto error1;
    }
    account_file = fopen(account_filename, "wx");
    if (account_file == NULL) {
        error_set(state, ERROR_CODE_ACCOUNT_FILE_OPEN);
        goto error1;
    }
    delete_account_file = 1;
    get_status(state, &sim_status, NULL, &call_status);
    if (error_check(state))
        goto error2;
    switch (sim_status) {
    case 1:
        error_set(state, ERROR_CODE_NO_SIM);
        break;
    case 2:
        error_set(state, ERROR_CODE_PIN_LOCKED_SIM);
        break;
    case 3:
        error_set(state, ERROR_CODE_PUK_LOCKED_SIM);
    case 4:
        break;
    default:
        error_set_value(state, ERROR_CODE_SIM_STATUS_UNKNOWN, sim_status);
    }
    if (sim_status != 4) {
        free(call_status);
        goto error2;
    }
    do_connect = 1;
    if (strcmp(call_status, "connected") == 0) {
        log_print(state, LOG_NOTICE, "already connected\n");
        do_connect = 0;
    } else if (strcmp(call_status, "disconnected") != 0) {
        error_set_info(state, ERROR_CODE_CALL_STATUS_UNKNOWN, call_status);
        goto error2;
    }
    free(call_status);
    if (do_connect) {
        dl_connect(state, 1);
        if (error_check(state))
            goto error2;
        log_print(state, LOG_INFO, "connected\n");
    }
    get_statistics(state, 1, 4, NULL, NULL, NULL, NULL, NULL);
    if (error_check(state))
        goto error3;
    if (fprintf(account_file, "0 0\n") < 0) {
        error_set(state, ERROR_CODE_ACCOUNT_FILE_WRITE);
        goto error3;
    }
    if (fseek(account_file, 0L, SEEK_SET) == -1) {
        error_set(state, ERROR_CODE_ACCOUNT_FILE_SEEK);
        goto error3;
    }
    /* This is the parent process */
    if (daemon(0, 0) == -1) {
        error_set(state, ERROR_CODE_DAEMON);
        goto error3;
    }
    delete_account_file = 0;
    /*
     * Process is daemonized -- stop writing to the terminal.
     */
    state->mode &= ~LOG_MODE_STDERR;
    /* This is the child process: we can NOW store the PID */
    if (pidfile_write(pid_file) == -1) {
        error_set(state, ERROR_CODE_PID_FILE_WRITE);
        goto error3;
    }
    if (cap > 0LL) {
        if (run_daemon_capped(state, pid_file, account_file, cap, enforce_cap))
            goto error2;
    } else {
        if (run_daemon(state, pid_file, account_file))
            goto error2;
    }

error3:
    dl_connect(state, 0);
    if (!error_check(state))
        log_print(state, LOG_INFO, "disconnected\n");

error2:
    if (fclose(account_file) != 0)
        error_set(state, ERROR_CODE_ACCOUNT_FILE_CLOSE);
    if (delete_account_file && (unlink(account_filename) == -1))
        error_set(state, ERROR_CODE_ACCOUNT_FILE_UNLINK);

error1:
    if (pidfile_remove(pid_file) == -1)
        error_set(state, ERROR_CODE_PID_FILE_REMOVE);
}

static void
fix_ip(char *ip)
{
    if (ip == NULL)
        return;
    size_t i = 0;
    size_t n = strlen(ip);
    size_t s = n + 1;
    char buffer[n];
    strncpy(buffer, ip, n);
    while (s > 0) {
        for (n = --s; s > 0; --s)
            if (buffer[s - 1] == '.')
                break;
        if (i > 0)
            ip[i++] = '.';
        strncpy(&ip[i], &buffer[s], n - s);
        i += n - s;
    }
}

static char **
get_dns(struct state *state)
{
    char **dns = (char **)malloc(3 * sizeof(char *));
    if (dns == NULL) {
        error_set(state, ERROR_CODE_MEMORY);
        return NULL;
    }
    get_statistics(state, 0, 4, NULL, NULL, NULL, &dns[0], &dns[1]);
    if (error_check(state)) {
        free(dns);
        return NULL;
    }
    if ((dns[0] != NULL) && (dns[1] != NULL) && (strcmp(dns[0], dns[1]) == 0)) {
        free(dns[1]);
        dns[1] = NULL;
    }
    if (dns[0] == NULL) {
        dns[0] = dns[1];
        dns[1] = NULL;
    } else {
        dns[2] = NULL;
        fix_ip(dns[1]);
    }
    fix_ip(dns[0]);
    return dns;
}

static void
stop_monitor(struct state *state, const char *pid_filename)
{
    char *call_status;
    pid_t pid;
    struct pidfh *pid_file;
    pid_file = pidfile_open(pid_filename, PID_FILE_MODE, &pid);
    if (pid_file == NULL) {
        if (errno != EEXIST) {
            error_set(state, ERROR_CODE_PID_FILE_OPEN);
            return;
        }
        if (kill(pid, SIGTERM) == -1)
            error_set(state, ERROR_CODE_KILL);
        return;
    }
    if (pidfile_remove(pid_file) == -1) {
        error_set(state, ERROR_CODE_PID_FILE_REMOVE);
        return;
    }
    log_print(state, LOG_INFO, "monitor is not running\n");
    get_status(state, NULL, NULL, &call_status);
    if (error_check(state))
        return;
    if (strcmp(call_status, "connected") == 0) {
        free(call_status);
        dl_connect(state, 0);
        if (error_check(state))
            return;
        error_set(state, ERROR_CODE_CONNECTED);
        return;
    }
    if (strcmp(call_status, "disconnected") == 0) {
        free(call_status);
        return;
    }
    error_set_info(state, ERROR_CODE_CALL_STATUS_UNKNOWN, call_status);
}

static void
decode_entities(char *text)
{
    int c, n;
    char *p, *q;
    text = strchr(text, '&');
    if (text == NULL)
        return;
    for (n = 0, p = text; p[0] != '\0'; ++p) {
        switch (n) {
        case 3:
            n = 0;
            errno = 0;
            c = (int)strtol(p, &q, 16);
            if ((errno == 0) && (q[0] == ';') && (c > 0) && (c < 256)) {
                (text++)[0] = (char)c;
                p = q;
                continue;
            }
            (text++)[0] = '&';
            (text++)[0] = '#';
            (text++)[0] = 'x';
            --p;
            break;
        case 2:
            if (p[0] == 'x') {
                n = 3;
            } else {
                n = 0;
                (text++)[0] = '&';
                (text++)[0] = '#';
                --p;
            }
            break;
        case 1:
            if (p[0] == '#') {
                n = 2;
            } else {
                n = 0;
                (text++)[0] = '&';
                --p;
            }
            break;
        default:
            if (p[0] == '&') {
                n = 1;
            } else {
                (text++)[0] = p[0];
            }
        }
    }
    switch (n) {
    case 3:
        (text++)[0] = '&';
        (text++)[0] = '#';
        (text++)[0] = 'x';
        break;
    case 2:
        (text++)[0] = '&';
        (text++)[0] = '#';
        break;
    case 1:
        (text++)[0] = '&';
    }
    (text++)[0] = '\0';
}

static struct sm *
sm_build(struct state *state, const cJSON *entry)
{
    int type, index;
    char *s;
    size_t size;
    struct sm *sm;
    const cJSON *jtype, *jindex, *msisdn, *text, *time;
    jtype = cJSON_GetObjectItemCaseSensitive(entry, SMS_READ_ENTRY_TYPE);
    if (!cJSON_IsString(jtype) || (jtype->valuestring == NULL)) {
        error_set(state, ERROR_CODE_ENTRY_TYPE_MISSING);
        return NULL;
    }
    errno = 0;
    type = (int)strtol(jtype->valuestring, NULL, 10);
    if (errno != 0) {
        error_set_info_dup(state, ERROR_CODE_ENTRY_TYPE_INVALID,
                           jtype->valuestring);
        return NULL;
    }
    jindex = cJSON_GetObjectItemCaseSensitive(entry, SMS_READ_ENTRY_INDEX);
    if (!cJSON_IsString(jindex) || (jindex->valuestring == NULL)) {
        error_set(state, ERROR_CODE_ENTRY_INDEX_MISSING);
        return NULL;
    }
    index = (int)strtol(jindex->valuestring, NULL, 10);
    if (errno != 0) {
        error_set_info_dup(state, ERROR_CODE_ENTRY_INDEX_INVALID,
                           jindex->valuestring);
        return NULL;
    }
    msisdn = cJSON_GetObjectItemCaseSensitive(entry, SMS_READ_ENTRY_MSISDN);
    if (!cJSON_IsString(msisdn) || (msisdn->valuestring == NULL)) {
        error_set(state, ERROR_CODE_ENTRY_MSISDN_MISSING);
        return NULL;
    }
    text = cJSON_GetObjectItemCaseSensitive(entry, SMS_READ_ENTRY_TEXT);
    if (!cJSON_IsString(text) || (text->valuestring == NULL)) {
        error_set(state, ERROR_CODE_ENTRY_TEXT_MISSING);
        return NULL;
    }
    time = cJSON_GetObjectItemCaseSensitive(entry, SMS_READ_ENTRY_TIME);
    if (!cJSON_IsString(time) || (time->valuestring == NULL)) {
        error_set(state, ERROR_CODE_ENTRY_TIME_MISSING);
        return NULL;
    }
    decode_entities(text->valuestring);
    size = strlen(msisdn->valuestring);
    size += strlen(text->valuestring);
    size += strlen(time->valuestring);
    size += 3;
    size *= sizeof(char);
    size += sizeof(struct sm);
    sm = (struct sm *)malloc(size);
    if (sm == NULL) {
        error_set(state, ERROR_CODE_MEMORY);
        return NULL;
    }
    sm->type = type;
    sm->index = index;
    s = (char *)&sm[1];
    sm->msisdn = s;
    s = stpcpy(s, msisdn->valuestring);
    sm->text = ++s;
    s = stpcpy(s, text->valuestring);
    sm->time = ++s;
    strcpy(s, time->valuestring);
    return sm;
}

static struct sm **
sms_list(struct state *state, int storage, int box, int *count)
{
    int i, n;
    char buffer[sizeof(SMS_READ)];
    cJSON *response;
    struct sm *sm_entry;
    struct sm **sm_list = NULL;
    const cJSON *entries, *entry, *result;
    n = snprintf(buffer, sizeof(buffer), SMS_READ, storage, box);
    if (n < 0) {
        error_set(state, ERROR_CODE_SNPRINTF);
        return NULL;
    }
    if (n >= sizeof(buffer)) {
        error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
        return NULL;
    }
    response = qcmap_post(state, buffer, n);
    if (response == NULL)
        return NULL;
    result = cJSON_GetObjectItemCaseSensitive(response, SMS_READ_RESULT);
    if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(result->valuestring, "SUCCESS") != 0) {
        error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                           result->valuestring);
        goto error1;
    }
    entries = cJSON_GetObjectItemCaseSensitive(response, SMS_READ_ENTRY);
    if (!cJSON_IsArray(entries)) {
        error_set(state, ERROR_CODE_ENTRIES_MISSING);
        goto error1;
    }
    *count = n = cJSON_GetArraySize(entries);
    if (n == 0)
        goto error1;
    sm_list = (struct sm **)malloc(n * sizeof(struct sm *));
    if (sm_list == NULL) {
        error_set(state, ERROR_CODE_MEMORY);
        goto error1;
    }
    for (i = 0; i < n; ++i) {
        entry = cJSON_GetArrayItem(entries, i);
        if (!cJSON_IsObject(entry)) {
            error_set(state, ERROR_CODE_ENTRIES_INVALID);
            break;
        }
        sm_entry = sm_build(state, entry);
        if (sm_entry == NULL)
            break;
        sm_list[i] = sm_entry;
    }
    if (i < n) {
        while (i > 0)
            free(sm_list[--i]);
        free(sm_list);
        sm_list = NULL;
    }

error1:
    cJSON_free(response);
    return sm_list;
}

/*
 * Compute the value for the 'msgFlag' parameter.
 */
static int
check_message(const char *text, int *type, size_t *length)
{
    int n = 0;
    unsigned char c;
    *type = 0;
    *length = 0U;
    while (text[0] != '\0') {
        c = (unsigned char)text[0];
        if (n > 0) {
            if ((c & 0xc0U) != 0x80U)
                return -1;
            if (--n == 0)
                ++*length;
        } else if ((c & 0x80U) != 0) {
            *type = 1;
            for (c <<= 1; (c & 0x80U) != 0; c <<= 1)
                ++n;
            if ((n < 1) || (n > 5))
                return -1;
        } else {
            switch (c) {
            case '\f':
            case '[': case '\\': case ']': case '^':
            case '{': case '|': case '}': case '~':
                *type = 1;
            }
            ++*length;
        }
        ++text;
    }
    if (n > 0)
        return -1;
    return 0;
}

static void
sms_store(struct state *state, int storage, const char *tpda, const char *text)
{
    int mtype, n, value;
    cJSON *response;
    const cJSON *result, *storage_type;
    size_t textl;
    if (check_message(text, &mtype, &textl) == -1) {
        error_set(state, ERROR_CODE_MESSAGE_INVALID);
        return;
    }
    if (mtype == 0) {
        if (textl > SMS_TYPE_0_MAX_LENGTH) {
            error_set_value(state, ERROR_CODE_MESSAGE_TOO_LONG,
                            SMS_TYPE_0_MAX_LENGTH);
            return;
        }
    } else {
        if (textl > SMS_TYPE_1_MAX_LENGTH) {
            error_set_value(state, ERROR_CODE_MESSAGE_TOO_LONG,
                            SMS_TYPE_1_MAX_LENGTH);
            return;
        }
    }
    response = qcmap_post(state, GET_SMS_STORAGE_TYPE,
                          sizeof(GET_SMS_STORAGE_TYPE) - 1);
    if (response == NULL)
        return;
    result = cJSON_GetObjectItemCaseSensitive(response,
                                              GET_SMS_STORAGE_TYPE_RESULT);
    if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(result->valuestring, "SUCCESS") != 0) {
        error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                           result->valuestring);
        goto error1;
    }
    storage_type =
        cJSON_GetObjectItemCaseSensitive(response,
                                         GET_SMS_STORAGE_TYPE_STORAGE_TYPE);
    if (!cJSON_IsString(storage_type) || (storage_type->valuestring == NULL)) {
        error_set(state, ERROR_CODE_STORAGE_TYPE_MISSING);
        goto error1;
    }
    errno = 0;
    value = (int)strtol(storage_type->valuestring, NULL, 10);
    if (errno != 0) {
        error_set_info_dup(state, ERROR_CODE_STORAGE_TYPE_INVALID,
                           storage_type->valuestring);
        goto error1;
    }
    cJSON_free(response);
    if (value != storage) {
        char buffer[sizeof(SET_SMS_STORAGE_TYPE)];
        n = snprintf(buffer, sizeof(buffer), SET_SMS_STORAGE_TYPE, storage);
        if (n < 0) {
            error_set(state, ERROR_CODE_SNPRINTF);
            return;
        }
        if (n >= sizeof(buffer)) {
            error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
            return;
        }
        response = qcmap_post(state, buffer, n);
        if (response == NULL)
            return;
        result = cJSON_GetObjectItemCaseSensitive(response,
                                                  SET_SMS_STORAGE_TYPE_RESULT);
        if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
            error_set(state, ERROR_CODE_RESULT_MISSING);
            goto error1;
        }
        if (strcmp(result->valuestring, "SUCCESS") != 0) {
            error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                               result->valuestring);
            goto error1;
        }
        cJSON_free(response);
    }
    {
        char buffer[sizeof(SMS_SAVE) + strlen(tpda) + strlen(text)];
        const cJSON *failed, *success;
        n = snprintf(buffer, sizeof(buffer), SMS_SAVE,
                     mtype, textl, tpda, text);
        if (n < 0) {
            error_set(state, ERROR_CODE_SNPRINTF);
            return;
        }
        if (n >= sizeof(buffer)) {
            error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
            return;
        }
        response = qcmap_post(state, buffer, n);
        if (response == NULL)
            return;
        result = cJSON_GetObjectItemCaseSensitive(response, SMS_SAVE_RESULT);
        if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
            error_set(state, ERROR_CODE_RESULT_MISSING);
            goto error1;
        }
        if (strcmp(result->valuestring, "SUCCESS") != 0) {
            error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                               result->valuestring);
            goto error1;
        }
        success = cJSON_GetObjectItemCaseSensitive(response, SMS_SAVE_MSG_SUCCESS);
        if (!cJSON_IsString(success) || (success->valuestring == NULL)) {
            error_set(state, ERROR_CODE_MSG_SUCCESS_MISSING);
            goto error1;
        }
        errno = 0;
        value = (int)strtol(success->valuestring, NULL, 10);
        if ((errno != 0) || (value != 1)) {
            error_set_info_dup(state, ERROR_CODE_MSG_SUCCESS_INVALID,
                               success->valuestring);
            goto error1;
        }
        failed = cJSON_GetObjectItemCaseSensitive(response, SMS_SAVE_MSG_FAILED);
        if (!cJSON_IsString(failed) || (failed->valuestring == NULL)) {
            error_set(state, ERROR_CODE_MSG_FAILED_MISSING);
            goto error1;
        }
        value = (int)strtol(failed->valuestring, NULL, 10);
        if ((errno != 0) || (value != 0))
            error_set_info_dup(state, ERROR_CODE_MSG_FAILED_INVALID,
                               success->valuestring);
    }

error1:
    cJSON_free(response);
}

static void
sms_delete(struct state *state, int storage, int box, int index)
{
    int n;
    char buffer[sizeof(SMS_DELETE) + 20];
    cJSON *response;
    const cJSON *result;
    n = snprintf(buffer, sizeof(buffer), SMS_DELETE, storage, box, index);
    if (n < 0) {
        error_set(state, ERROR_CODE_SNPRINTF);
        return;
    }
    if (n >= sizeof(buffer)) {
        error_set_value(state, ERROR_CODE_SMALL_BUFFER, __LINE__);
        return;
    }
    response = qcmap_post(state, buffer, n);
    if (response == NULL)
        return;
    result = cJSON_GetObjectItemCaseSensitive(response, SMS_DELETE_RESULT);
    if (!cJSON_IsString(result) || (result->valuestring == NULL)) {
        error_set(state, ERROR_CODE_RESULT_MISSING);
        goto error1;
    }
    if (strcmp(result->valuestring, "SUCCESS") != 0)
        error_set_info_dup(state, ERROR_CODE_RESULT_INVALID,
                           result->valuestring);

error1:
    cJSON_free(response);
}

static int
parse_storage(struct state *state, const char *arg, int *storage)
{
    if (strcasecmp(arg, "sim") == 0) {
        *storage = 0;
        return 0;
    }
    if (strcasecmp(arg, "me") == 0) {
        *storage = 1;
        return 0;
    }
    fprintf(stderr, "%s: invalid storage: \"%s\"\n\n", state->name, arg);
    return -1;
}

static int
parse_box(struct state *state, const char *arg, int *box)
{
    if (strcasecmp(arg, "inbox") == 0) {
        *box = 0;
        return 0;
    }
    if (strcasecmp(arg, "outbox") == 0) {
        *box = 2;
        return 0;
    }
    fprintf(stderr, "%s: invalid box: \"%s\"\n\n", state->name, arg);
    return -1;
}

static int
parse_index(struct state *state, const char *arg, int *index)
{
    errno = 0;
    *index = (int)strtol(arg, NULL, 10);
    if ((errno == 0) && (*index >= 0))
        return 0;
    fprintf(stderr, "%s: invalid index: \"%s\"\n\n", state->name, arg);
    return -1;
}

static void
print_sm(struct sm *sms)
{
    const char *type;
    switch (sms->type) {
    case SM_TYPE_READ:
        type = "READ";
        break;
    case SM_TYPE_UNREAD:
        type = "UNREAD";
        break;
    case SM_TYPE_SENT:
        type = "SENT";
        break;
    case SM_TYPE_UNSENT:
        type = "UNSENT";
        break;
    default:
        type = "UNDEFINED";
    }
    fprintf(stdout, "%d %s %s %s %s\n", sms->index,
            sms->time, type, sms->msisdn, sms->text);
}

int
main(int argc, char *argv[])
{
    int opt;
    int enforce_cap = 0;
    long long cap = 0LL;
    const char *cmd;
    struct state state;
    state.name = PACKAGE_NAME;
    state.host = QCMAP_DEFAULT_HOST;
    state.mode = LOG_MODE_STDERR;
#ifdef USE_LIBCURL
    state.curl_initialized = 0;
    state.handle = NULL;
    state.url = NULL;
    state.error_buffer[0] = '\0';
#endif
    while ((opt = getopt(argc, argv, "c:h:lqs")) != -1) {
        switch (opt) {
        case 'c':
            errno = 0;
            cap = strtoll(optarg, NULL, 10);
            if ((errno != 0) || (cap < 1LL)) {
                fprintf(stderr, "%s: invalid cap: \"%s\"\n\n",
                        state.name, optarg);
                return EXIT_CODE_INVALID_ARGUMENT;
            }
            break;
        case 'h':
            state.host = optarg;
            break;
        case 'l':
            enforce_cap = 1;
            break;
        case 'q':
            state.mode &= ~LOG_MODE_STDERR;
            break;
        case 's':
            state.mode |= LOG_MODE_SYSLOG;
            break;
        default:
            return EXIT_CODE_INVALID_ARGUMENT;
        }
    }
    argc -= optind;
    argv = &argv[optind];
    if (argc < 1) {
        fprintf(stdout, USAGE);
        return EXIT_CODE_SUCCESS;
    }
#ifdef USE_FETCH
    fetchTimeout = HTTP_TRANSFER_TIMEOUT;
#endif
    cmd = argv[0];
    error_init(&state);
    if (strcmp(cmd, "iccid") == 0) {
        char *iccid = get_iccid(&state);
        if (iccid != NULL) {
            fprintf(stdout, "%s\n", iccid);
            free(iccid);
        }
    } else if (strcmp(cmd, "unlock") == 0) {
        if (argc < 2)
            goto error2;
        unlock_sim(&state, argv[1]);
    } else if (strcmp(cmd, "reset_pin") == 0) {
        if (argc < 3)
            goto error2;
        reset_pin(&state, argv[1], argv[2]);
    } else if (strcmp(cmd, "connect") == 0) {
        if (argc < 3)
            goto error2;
        start_monitor(&state, argv[1], argv[2], cap, enforce_cap);
    } else if (strcmp(cmd, "dns") == 0) {
        char **dns = get_dns(&state);
        if (dns != NULL) {
            for (int i = 0; dns[i] != NULL; ++i) {
                fprintf(stdout, "%s\n", dns[i]);
                free(dns[i]);
            }
            free(dns);
        }
    } else if (strcmp(cmd, "disconnect") == 0) {
        if (argc < 2)
            goto error2;
        stop_monitor(&state, argv[1]);
    } else if (strcmp(cmd, "sms") == 0) {
        if (argc < 2)
            goto error2;
        cmd = argv[1];
        if (strcmp(cmd, "list") == 0) {
            int box, count, storage;
            struct sm **sm_list;
            if (argc < 4)
                goto error2;
            if (parse_storage(&state, argv[2], &storage) == -1)
                goto error1;
            if (parse_box(&state, argv[3], &box) == -1)
                goto error1;
            sm_list = sms_list(&state, storage, box, &count);
            if (sm_list != NULL)
                for (box = 0; box < count; ++box)
                    print_sm(sm_list[box]);
        } else if (strcmp(cmd, "store") == 0) {
            int storage;
            if (argc < 5)
                goto error2;
            if (parse_storage(&state, argv[2], &storage) == -1)
                goto error1;
            sms_store(&state, storage, argv[3], argv[4]);
        } else if (strcmp(cmd, "delete") == 0) {
            int box, index, storage;
            if (argc < 5)
                goto error2;
            if (parse_storage(&state, argv[2], &storage) == -1)
                goto error1;
            if (parse_box(&state, argv[3], &box) == -1)
                goto error1;
            if (parse_index(&state, argv[4], &index) == -1)
                goto error1;
            sms_delete(&state, storage, box, index);
        } else {
            fprintf(stderr, "%s: invalid sms subcommand: \"%s\"\n\n",
                    state.name, cmd);
            goto error1;
        }
    } else {
        fprintf(stderr, "%s: invalid command: \"%s\"\n\n", state.name, cmd);
        goto error1;
    }
#ifdef USE_LIBCURL
    if (state.curl_initialized) {
        if (state.handle != NULL)
            curl_easy_cleanup(state.handle);
        if (state.url != NULL)
            curl_url_cleanup(state.url);
        curl_global_cleanup();
    }
#endif
    if (error_check(&state)) {
        error_print(&state);
        error_fini(&state);
    }
    return error_to_exit_code(&state);

error2:
    fprintf(stderr, "%s: not enough arguments\n\n", state.name);

error1:
    fprintf(stderr, USAGE);
    return EXIT_CODE_INVALID_ARGUMENT;
}
