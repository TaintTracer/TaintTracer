#include <ctype.h>
#include <fcntl.h>
#include <optional>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <string>
#include "logging.h"
#include "Debugging.h"
#include "../debugger/Config.h"

constexpr size_t max_logfile_size = 1 << 30;
static FILE *f = NULL;
size_t bytes_witten = 0;

void android_log_setup(const char *path) {
    f = fopen(path, "a");
    if (!f) {
        __android_log_print(ANDROID_LOG_ERROR, "log_wrapper", "Failed to open log file for writing: %s", strerror(errno));
        abort();
    }
    __android_log_print(ANDROID_LOG_INFO, "log_wrapper", "Opened log file for writing: %s", path);
}

int android_log_print_wrapper(int prio, const char* tag, const char* fmt, ...) {
    // Avoid LOG* macros, since it depends on this function itself
    // TODO: Chagne all __android_log_print stuff to LOGV?
    va_list arg_list;
    va_start(arg_list, fmt);
    if (f && bytes_witten < max_logfile_size) {
        // Print time in the same format as logcat
        std::string time {};
        {
            using namespace std::chrono;
            auto now = system_clock::now();
            auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
            auto timer = system_clock::to_time_t(now);
            std::tm tm = *std::localtime(&timer);

            std::ostringstream oss;
            oss << std::put_time(&tm, "%m-%d %H:%M:%S");
            oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
            time =  oss.str();
        }
        bytes_witten += fprintf(f, "%s ", time.c_str());
        va_list arg_list_f;
        va_copy(arg_list_f, arg_list);
        bytes_witten += vfprintf(f, fmt, arg_list);
        va_end(arg_list_f);
        fflush(f);
        if (bytes_witten >= max_logfile_size) {
            fprintf(f, "\n!!! STOPPING android_log_print_wrapper FILE EXCEEDS 1GiB !!!");
        }
    }
    if (Config::log_to_logcat) {
        int res = __android_log_vprint(prio, tag, fmt, arg_list);
    }
    va_end(arg_list);
    return 0; // HACK: Returning dummy value
}

int android_printf(const char *format, ...) {
    static char line_buffer[1024];
    static size_t chars_in_buffer = 0;
    va_list arg_list;
    va_start(arg_list, format);
    int res = vsprintf(&line_buffer[chars_in_buffer], format, arg_list);
    if (res < 0) {
        LOGE("vsprintf failed");
    }
    chars_in_buffer += res;
    assert(chars_in_buffer < sizeof(line_buffer));
    char *newline;
    while ((newline = strchr(line_buffer, '\n')) != 0) {
        size_t chars_to_print = newline - line_buffer + 1;
        // TODO: empty lines don't show up on logcat
        // Write line including newline character to logcat (and a logfile when enabled)
        android_log_print_wrapper(ANDROID_LOG_VERBOSE, LOG_TAG, "%.*s", (int) chars_to_print, line_buffer);
        memmove(line_buffer, line_buffer + chars_to_print, chars_in_buffer - chars_to_print);
        chars_in_buffer -= chars_to_print;
        line_buffer[chars_in_buffer] = 0;
    }
    va_end(arg_list);
    return res;
}

void android_hexdump(const unsigned char *ptr, size_t size, size_t label_offset) {
    unsigned char *buf = (unsigned char *) ptr;
    int i, j;
    for (i = 0; i < size; i += 16) {
        android_printf("%06x: ", label_offset + i);
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                android_printf("%02x ", buf[i + j]);
            } else {
                android_printf("   ");
            }
        }
        android_printf(" ");
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                android_printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        android_printf("\n");
    }
}
