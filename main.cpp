// main.cpp
//
// Place at: module/jni/main.cpp
// in topjohnwu's zygisk-module-sample template
// (https://github.com/topjohnwu/zygisk-module-sample).
//
// Forces Spotify's native AAudio streams to report
// AAUDIO_ALLOW_CAPTURE_BY_ALL (1) instead of whatever policy Spotify
// actually requests, by PLT-hooking AAudioStreamBuilder_setAllowedCapturePolicy
// in every loaded library that imports it, using Zygisk's own built-in
// pltHookRegister/pltHookCommit API (no external hooking library needed).
//
// Deliberately written WITHOUT the C++ STL (no std::string/vector/set),
// so it builds with APP_STL := none in Application.mk and needs no
// submodule. All buffers are fixed-size and all parsing is done with
// plain C.
//
// This is UNCOMPILED, UNTESTED source — build it with a real NDK/ndk-build
// before flashing. Keep a way to disable Zygisk modules from recovery
// before testing, since this runs inside Spotify's zygote-forked process.

#include <android/log.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "zygisk.hpp"

#define LOG_TAG "AAudioCaptureFix"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static const char *TARGET_PACKAGE = "com.spotify.music";
static const char *HOOK_SYMBOL = "AAudioStreamBuilder_setAllowedCapturePolicy";

// aaudio/AAudio.h value, redeclared so this file has no dependency on the
// AAudio NDK headers being on the include path.
static const int32_t AAUDIO_ALLOW_CAPTURE_BY_ALL = 1;

// Signature per AAudio.h:
//   aaudio_result_t AAudioStreamBuilder_setAllowedCapturePolicy(
//       AAudioStreamBuilder* builder, int32_t capturePolicy);
typedef int32_t (*setAllowedCapturePolicy_t)(void *builder, int32_t policy);

static setAllowedCapturePolicy_t g_orig = nullptr;
static zygisk::Api *g_api = nullptr;

static int32_t hook_setAllowedCapturePolicy(void *builder, int32_t policy) {
    if (policy != AAUDIO_ALLOW_CAPTURE_BY_ALL) {
        LOGI("setAllowedCapturePolicy(%d) -> forced to ALLOW_ALL", policy);
    }
    return g_orig(builder, AAUDIO_ALLOW_CAPTURE_BY_ALL);
}

// Fixed-size table of (dev, inode) pairs we've already registered a hook
// attempt against, so repeated scans don't re-register the same mapped
// file over and over.
#define MAX_SEEN 512
static dev_t seen_dev[MAX_SEEN];
static ino_t seen_ino[MAX_SEEN];
static int seen_count = 0;

static bool already_seen(dev_t dev, ino_t ino) {
    for (int i = 0; i < seen_count; i++) {
        if (seen_dev[i] == dev && seen_ino[i] == ino) return true;
    }
    return false;
}

static void mark_seen(dev_t dev, ino_t ino) {
    if (seen_count < MAX_SEEN) {
        seen_dev[seen_count] = dev;
        seen_ino[seen_count] = ino;
        seen_count++;
    }
}

// Parses /proc/self/maps and calls pltHookRegister for every distinct
// mapped file not already seen. pltHookRegister only actually patches a
// library if that library's PLT/GOT imports HOOK_SYMBOL, so calling it
// for every mapped file is safe and is the normal way this API is used.
static void scan_and_hook() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == nullptr) {
        LOGW("failed to open /proc/self/maps");
        return;
    }

    char line[512];
    bool registered_any = false;

    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long start, end, offset, inode;
        char perms[8];
        unsigned major, minor;
        int path_offset = 0;

        int n = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n",
                        &start, &end, perms, &offset, &major, &minor,
                        &inode, &path_offset);
        if (n < 7 || inode == 0 || path_offset == 0) continue;

        char *path = line + path_offset;
        size_t len = strlen(path);
        while (len > 0 && (path[len - 1] == '\n' || path[len - 1] == ' ')) {
            path[--len] = '\0';
        }
        while (*path == ' ') path++;
        if (*path == '\0') continue;
        // Skip pseudo-paths like [heap], [stack], [vdso], etc.
        if (path[0] == '[') continue;

        dev_t dev = makedev(major, minor);
        ino_t ino = (ino_t) inode;
        if (already_seen(dev, ino)) continue;
        mark_seen(dev, ino);

        bool ok = g_api->pltHookRegister(
            dev, ino, HOOK_SYMBOL,
            reinterpret_cast<void *>(hook_setAllowedCapturePolicy),
            reinterpret_cast<void **>(&g_orig));
        if (ok) {
            registered_any = true;
            LOGI("registered against %s", path);
        }
    }
    fclose(maps);

    if (registered_any) {
        if (g_api->pltHookCommit()) {
            LOGI("hook committed");
        } else {
            LOGW("pltHookCommit failed");
        }
    }
}

static void *scan_thread_main(void *) {
    // Spotify may not touch AAudio until playback starts, and it may
    // load its native audio libraries lazily. Rescan periodically for a
    // few minutes to catch that, then stop.
    const int interval_ms = 1000;
    const int max_scans = 180; // ~3 minutes
    int extra_after_hook = 0;

    for (int i = 0; i < max_scans; i++) {
        scan_and_hook();
        if (g_orig != nullptr) {
            // Already hooked at least once; do a couple more passes to
            // catch any libraries loaded shortly after, then stop.
            if (++extra_after_hook > 3) break;
        }
        usleep(interval_ms * 1000);
    }
    return nullptr;
}

class AAudioCaptureFixModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        g_api = api;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *nice_name = nullptr;
        if (args != nullptr && args->nice_name != nullptr) {
            nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }

        is_target = (nice_name != nullptr && strcmp(nice_name, TARGET_PACKAGE) == 0);

        if (nice_name != nullptr) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }

        if (!is_target) {
            // Not Spotify: unload ourselves from this process.
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!is_target) return;

        LOGI("loaded into %s, starting capture-policy hook", TARGET_PACKAGE);

        pthread_t t;
        pthread_create(&t, nullptr, scan_thread_main, nullptr);
        pthread_detach(t);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool is_target = false;
};

REGISTER_ZYGISK_MODULE(AAudioCaptureFixModule)
