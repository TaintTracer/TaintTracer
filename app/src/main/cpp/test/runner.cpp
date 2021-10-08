// #define CATCH_CONFIG_ANDROID_LOGWRITE
// #define CATCH_CONFIG_NOSTDOUT
/*
 * Call std::terminate, and thus abort() when an exception is thrown.
 * This will dump a stack trace when an exception is thrown.
 */
#define CATCH_CONFIG_DISABLE_EXCEPTIONS
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#ifdef CATCH_CONFIG_NOSTDOUT
class out_buff : public std::stringbuf {
    std::FILE* m_stream;
public:
    out_buff(std::FILE* stream):m_stream(stream) {}
    ~out_buff();
    int sync() {
        int ret = 0;
        __android_log_write(ANDROID_LOG_DEBUG, "TaintTracerTestRunner", str().c_str());
        // Reset the buffer to avoid printing it multiple times
        str("");
        return ret;
    }
};

out_buff::~out_buff() { pubsync(); }

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wexit-time-destructors" // static variables in cout/cerr/clog
#endif

namespace Catch {
    std::ostream& cout() {
        static std::ostream ret(new out_buff(stdout));
        return ret;
    }
    std::ostream& clog() {
        static std::ostream ret(new out_buff(stderr));
        return ret;
    }
    std::ostream& cerr() {
        return clog();
    }
}

#endif
