/**
 * Native Root Detection Library (C++)
 * Provides low-level detection that's harder to hook from Java layer
 * 
 * To use: Compile as native library and call from Java via JNI
 */

#include <jni.h>
#include <string>
#include <vector>
#include <fstream>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <link.h>
#include <android/log.h>
#include <sys/system_properties.h>

#define LOG_TAG "NativeRootDetection"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

class NativeRootDetector {
public:
    /**
     * Main native detection method
     */
    static bool isDeviceRooted() {
        return detectSuBinary() ||
               detectMagiskNative() ||
               detectHooks() ||
               detectDebugging() ||
               detectSELinuxState() ||
               detectMemoryAnomalies() ||
               detectProcessTracing();
    }
    
    /**
     * Detect su binary using native file access
     */
    static bool detectSuBinary() {
        const char* suPaths[] = {
            "/system/bin/su",
            "/system/xbin/su", 
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            nullptr
        };
        
        for (int i = 0; suPaths[i] != nullptr; i++) {
            struct stat st;
            if (stat(suPaths[i], &st) == 0) {
                LOGW("Su binary found: %s", suPaths[i]);
                
                // Additional check: verify it's executable
                if (st.st_mode & S_IXUSR) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Native Magisk detection
     */
    static bool detectMagiskNative() {
        const char* magiskPaths[] = {
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/cache/.magisk",
            "/dev/.magisk",
            "/system/bin/magisk",
            "/sbin/magisk",
            nullptr
        };
        
        // Check file existence
        for (int i = 0; magiskPaths[i] != nullptr; i++) {
            if (access(magiskPaths[i], F_OK) == 0) {
                LOGW("Magisk path found: %s", magiskPaths[i]);
                return true;
            }
        }
        
        // Check for Magisk properties
        if (checkMagiskProperties()) {
            return true;
        }
        
        // Check for Magisk processes
        if (checkMagiskProcesses()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Detect function hooks at native level
     */
    static bool detectHooks() {
        // Method 1: Check PLT/GOT table integrity
        if (checkPLTIntegrity()) {
            return true;
        }
        
        // Method 2: Check for inline hooks
        if (checkInlineHooks()) {
            return true;
        }
        
        // Method 3: Check loaded libraries for hook frameworks
        if (checkSuspiciousLibraries()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check PLT/GOT table integrity
     */
    static bool checkPLTIntegrity() {
        // Get list of loaded libraries
        FILE* maps = fopen("/proc/self/maps", "r");
        if (!maps) return false;
        
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, ".so") && strstr(line, "r-xp")) {
                // Extract library path
                char* libPath = strrchr(line, ' ');
                if (libPath) {
                    libPath++; // Skip space
                    libPath[strcspn(libPath, "\n")] = 0; // Remove newline
                    
                    // Check if library is suspicious
                    if (strstr(libPath, "riru") || 
                        strstr(libPath, "xposed") ||
                        strstr(libPath, "substrate") ||
                        strstr(libPath, "frida")) {
                        LOGW("Suspicious library detected: %s", libPath);
                        fclose(maps);
                        return true;
                    }
                }
            }
        }
        fclose(maps);
        return false;
    }
    
    /**
     * Check for inline hooks by analyzing function prologues
     */
    static bool checkInlineHooks() {
        // Get address of a system function
        void* openFunc = dlsym(RTLD_DEFAULT, "open");
        if (openFunc) {
            unsigned char* funcPtr = (unsigned char*)openFunc;
            
            // Check if function starts with suspicious instructions
            // Common hook patterns: JMP, CALL to unexpected addresses
            if (funcPtr[0] == 0xE9 || // JMP rel32
                funcPtr[0] == 0xFF || // JMP/CALL with ModR/M
                (funcPtr[0] == 0x48 && funcPtr[1] == 0xB8)) { // MOV RAX, imm64
                LOGW("Possible inline hook detected in open()");
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check for suspicious loaded libraries
     */
    static bool checkSuspiciousLibraries() {
        struct android_namespace_t* ns = nullptr;
        void* handle = android_dlopen_ext("libc.so", RTLD_NOW, nullptr);
        
        if (handle) {
            // Check if any hook frameworks are loaded
            const char* hookLibs[] = {
                "libriru.so",
                "libxposed_bridge.so",
                "liblsposed.so",
                "libsubstrate.so",
                "libdobby.so",
                "libfrida-gadget.so",
                nullptr
            };
            
            for (int i = 0; hookLibs[i] != nullptr; i++) {
                void* hookHandle = dlopen(hookLibs[i], RTLD_NOW | RTLD_NOLOAD);
                if (hookHandle) {
                    LOGW("Hook library loaded: %s", hookLibs[i]);
                    dlclose(hookHandle);
                    dlclose(handle);
                    return true;
                }
            }
            dlclose(handle);
        }
        
        return false;
    }
    
    /**
     * Detect debugging/tracing
     */
    static bool detectDebugging() {
        // Check if we're being traced
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
            LOGW("Process is being traced");
            return true;
        }
        
        // Check TracerPid in /proc/self/status
        FILE* status = fopen("/proc/self/status", "r");
        if (status) {
            char line[256];
            while (fgets(line, sizeof(line), status)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int tracerPid = atoi(line + 10);
                    if (tracerPid != 0) {
                        LOGW("TracerPid detected: %d", tracerPid);
                        fclose(status);
                        return true;
                    }
                    break;
                }
            }
            fclose(status);
        }
        
        return false;
    }
    
    /**
     * Check SELinux enforcement state
     */
    static bool detectSELinuxState() {
        FILE* enforce = fopen("/sys/fs/selinux/enforce", "r");
        if (enforce) {
            char state;
            if (fread(&state, 1, 1, enforce) == 1) {
                fclose(enforce);
                if (state == '0') {
                    LOGW("SELinux is in permissive mode");
                    return true;
                }
            } else {
                fclose(enforce);
            }
        }
        return false;
    }
    
    /**
     * Detect memory anomalies
     */
    static bool detectMemoryAnomalies() {
        FILE* maps = fopen("/proc/self/maps", "r");
        if (!maps) return false;
        
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            // Check for executable and writable pages (rwxp)
            if (strstr(line, "rwxp")) {
                LOGW("RWX memory region detected: %s", line);
                fclose(maps);
                return true;
            }
            
            // Check for suspicious anonymous mappings
            if (strstr(line, "[anon:") && strstr(line, "rw-p")) {
                // Parse memory range
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    unsigned long size = end - start;
                    // Large anonymous regions might be suspicious
                    if (size > 0x100000) { // 1MB
                        LOGW("Large anonymous memory region: %lu bytes", size);
                        fclose(maps);
                        return true;
                    }
                }
            }
        }
        fclose(maps);
        return false;
    }
    
    /**
     * Detect process tracing/injection
     */
    static bool detectProcessTracing() {
        // Fork a child process to test ptrace
        pid_t child = fork();
        if (child == 0) {
            // Child process
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
                _exit(1); // Ptrace failed
            }
            _exit(0); // Success
        } else if (child > 0) {
            // Parent process
            int status;
            waitpid(child, &status, 0);
            
            if (WEXITSTATUS(status) == 1) {
                LOGW("Ptrace test failed - possible anti-debug");
                return true;
            }
        }
        
        return false;
    }
    
private:
    /**
     * Check Magisk-specific properties
     */
    static bool checkMagiskProperties() {
        const char* magiskProps[] = {
            "ro.magisk.version",
            "ro.magisk.versioncode", 
            "init.svc.magisk_daemon",
            "init.svc.magisk_pfs",
            nullptr
        };
        
        for (int i = 0; magiskProps[i] != nullptr; i++) {
            char value[PROP_VALUE_MAX];
            if (__system_property_get(magiskProps[i], value) > 0) {
                LOGW("Magisk property found: %s = %s", magiskProps[i], value);
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check for Magisk processes
     */
    static bool checkMagiskProcesses() {
        DIR* procDir = opendir("/proc");
        if (!procDir) return false;
        
        struct dirent* entry;
        while ((entry = readdir(procDir)) != nullptr) {
            if (strspn(entry->d_name, "0123456789") == strlen(entry->d_name)) {
                // This is a PID directory
                char cmdlinePath[256];
                snprintf(cmdlinePath, sizeof(cmdlinePath), "/proc/%s/cmdline", entry->d_name);
                
                FILE* cmdline = fopen(cmdlinePath, "r");
                if (cmdline) {
                    char cmd[256] = {0};
                    fread(cmd, 1, sizeof(cmd) - 1, cmdline);
                    fclose(cmdline);
                    
                    if (strstr(cmd, "magisk") || strstr(cmd, "magiskd")) {
                        LOGW("Magisk process found: %s", cmd);
                        closedir(procDir);
                        return true;
                    }
                }
            }
        }
        closedir(procDir);
        return false;
    }
};

/**
 * JNI interface functions
 */
extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_yourpackage_NativeRootDetection_isDeviceRooted(JNIEnv *env, jclass clazz) {
    return NativeRootDetector::isDeviceRooted();
}

JNIEXPORT jboolean JNICALL
Java_com_yourpackage_NativeRootDetection_detectSuBinary(JNIEnv *env, jclass clazz) {
    return NativeRootDetector::detectSuBinary();
}

JNIEXPORT jboolean JNICALL
Java_com_yourpackage_NativeRootDetection_detectMagiskNative(JNIEnv *env, jclass clazz) {
    return NativeRootDetector::detectMagiskNative();
}

JNIEXPORT jboolean JNICALL
Java_com_yourpackage_NativeRootDetection_detectHooks(JNIEnv *env, jclass clazz) {
    return NativeRootDetector::detectHooks();
}

JNIEXPORT jboolean JNICALL
Java_com_yourpackage_NativeRootDetection_detectDebugging(JNIEnv *env, jclass clazz) {
    return NativeRootDetector::detectDebugging();
}

} // extern "C"