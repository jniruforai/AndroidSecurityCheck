/**
 * Java interface for the native root detection library
 * This class provides JNI bindings to the C++ detection methods
 */
public class NativeRootDetection {
    
    // Load the native library
    static {
        System.loadLibrary("nativerootdetection");
    }
    
    /**
     * Comprehensive native root detection
     * @return true if device appears to be rooted
     */
    public static native boolean isDeviceRooted();
    
    /**
     * Detect su binary using native file access
     * @return true if su binary is found
     */
    public static native boolean detectSuBinary();
    
    /**
     * Native Magisk detection
     * @return true if Magisk is detected
     */
    public static native boolean detectMagiskNative();
    
    /**
     * Detect function hooks at native level
     * @return true if hooks are detected
     */
    public static native boolean detectHooks();
    
    /**
     * Detect debugging/tracing
     * @return true if debugging is detected
     */
    public static native boolean detectDebugging();
    
    /**
     * Java wrapper for comprehensive native detection
     * @return true if any native detection method triggers
     */
    public static boolean performNativeDetection() {
        try {
            return isDeviceRooted();
        } catch (UnsatisfiedLinkError e) {
            // Native library not available, fall back to Java detection
            android.util.Log.w("NativeRootDetection", "Native library not available");
            return false;
        } catch (Exception e) {
            android.util.Log.e("NativeRootDetection", "Native detection error", e);
            return true; // Assume compromised if native detection fails
        }
    }
    
    /**
     * Test individual native detection components
     * @return DetectionResult object with detailed results
     */
    public static DetectionResult performDetailedNativeDetection() {
        DetectionResult result = new DetectionResult();
        
        try {
            result.suBinaryDetected = detectSuBinary();
            result.magiskDetected = detectMagiskNative();
            result.hooksDetected = detectHooks();
            result.debuggingDetected = detectDebugging();
            result.overallResult = result.suBinaryDetected || result.magiskDetected || 
                                 result.hooksDetected || result.debuggingDetected;
        } catch (UnsatisfiedLinkError e) {
            result.nativeLibraryError = true;
            result.errorMessage = "Native library not available: " + e.getMessage();
        } catch (Exception e) {
            result.nativeLibraryError = true;
            result.errorMessage = "Native detection error: " + e.getMessage();
        }
        
        return result;
    }
    
    /**
     * Result class for detailed native detection
     */
    public static class DetectionResult {
        public boolean overallResult = false;
        public boolean suBinaryDetected = false;
        public boolean magiskDetected = false;
        public boolean hooksDetected = false;
        public boolean debuggingDetected = false;
        public boolean nativeLibraryError = false;
        public String errorMessage = "";
        
        @Override
        public String toString() {
            if (nativeLibraryError) {
                return "Native Detection Error: " + errorMessage;
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("Native Detection Results:\n");
            sb.append("Overall Result: ").append(overallResult).append("\n");
            sb.append("Su Binary: ").append(suBinaryDetected).append("\n");
            sb.append("Magisk: ").append(magiskDetected).append("\n");
            sb.append("Hooks: ").append(hooksDetected).append("\n");
            sb.append("Debugging: ").append(debuggingDetected);
            return sb.toString();
        }
    }
}