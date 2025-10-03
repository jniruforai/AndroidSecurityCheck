# Android Root Detection - Usage Examples

## Quick Start

### Basic Implementation

```java
// Simple usage in Activity onCreate
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Quick security check
        IntegratedSecurityManager security = new IntegratedSecurityManager(this);
        if (security.performComprehensiveSecurityCheck()) {
            // Device is compromised - handle accordingly
            showSecurityWarning();
            finish();
            return;
        }
        
        setContentView(R.layout.activity_main);
    }
    
    private void showSecurityWarning() {
        new AlertDialog.Builder(this)
            .setTitle("Security Warning")
            .setMessage("This app cannot run on rooted or modified devices.")
            .setPositiveButton("Exit", (dialog, which) -> finish())
            .setCancelable(false)
            .show();
    }
}
```

### Advanced Configuration

```java
public class SecureApplication extends Application {
    private IntegratedSecurityManager securityManager;
    
    @Override
    public void onCreate() {
        super.onCreate();
        
        // Configure security manager with custom settings
        securityManager = new IntegratedSecurityManager.Builder()
            .enableAdvancedDetection(true)
            .enableAntiBypass(true)
            .enableIntegrityVerification(true)
            .enableShamikoDetection(true)
            .enableNativeDetection(true)
            .enableContinuousMonitoring(true)
            .setMonitoringInterval(30) // 30 seconds
            .setMaxConsecutiveFailures(3)
            .exitOnDetection(true)
            .reportToServer(true, "https://your-server.com/security-report")
            .setDetectionTimeout(10) // 10 seconds
            .build(this);
        
        // Set security callback
        securityManager.setSecurityCallback(new SecurityCallbackImpl());
        
        // Start monitoring
        securityManager.startSecurityMonitoring();
    }
    
    private class SecurityCallbackImpl implements IntegratedSecurityManager.SecurityCallback {
        @Override
        public void onSecurityBreach(IntegratedSecurityManager.SecurityBreach breach, String details) {
            Log.w("Security", "Breach detected: " + breach + " - " + details);
            
            switch (breach) {
                case ROOT_DETECTED:
                    handleRootDetection(details);
                    break;
                case SHAMIKO_DETECTED:
                    handleShamikoDetection(details);
                    break;
                case INTEGRITY_SPOOFING_DETECTED:
                    handleIntegritySpoofing(details);
                    break;
                // Handle other breach types...
            }
        }
        
        @Override
        public void onSecurityCheckCompleted(boolean isSecure) {
            Log.d("Security", "Security check completed. Device secure: " + isSecure);
        }
        
        @Override
        public void onSecurityMonitoringStarted() {
            Log.i("Security", "Security monitoring started");
        }
        
        @Override
        public void onSecurityMonitoringStopped() {
            Log.i("Security", "Security monitoring stopped");
        }
    }
}
```

## Individual Component Usage

### 1. Advanced Root Detection

```java
AdvancedRootDetection detector = new AdvancedRootDetection(context);

// Comprehensive root detection
if (detector.isDeviceCompromised()) {
    Log.w("Security", "Device is compromised");
    // Handle accordingly
}

// Test specific detection methods
boolean magiskDetected = detector.detectMagiskWithDenialBypass();
boolean shamikoDetected = detector.detectShamikoModule();
boolean integrityCompromised = detector.detectIntegrityServiceSpoofing();
```

### 2. Anti-Bypass Detection

```java
AntiBypassDetection antiBypass = new AntiBypassDetection(context);

// Detect bypass attempts
if (antiBypass.detectBypassAttempts()) {
    Log.w("Security", "Bypass attempt detected");
    // Take immediate action
}

// Test specific bypass techniques
boolean denialListBypass = antiBypass.detectDenialListBypass();
boolean shamikoBypass = antiBypass.detectShamikoBypass();
boolean playIntegrityBypass = antiBypass.detectPlayIntegrityBypass();
```

### 3. Integrity Verification

```java
IntegrityVerification verifier = new IntegrityVerification(context);

// Comprehensive integrity check
if (verifier.verifyDeviceIntegrity()) {
    Log.w("Security", "Device integrity compromised");
    // Device may be using integrity spoofing
}

// Individual verification layers
boolean hardwareOk = verifier.performHardwareAttestation();
boolean softwareOk = verifier.performSoftwareIntegrityCheck();
boolean runtimeOk = verifier.verifyRuntimeEnvironment();
```

### 4. Shamiko-Specific Detection

```java
ShamikoSpecificDetection shamiko = new ShamikoSpecificDetection(context);

// Detect Shamiko module
if (shamiko.detectShamiko()) {
    Log.w("Security", "Shamiko module detected");
    // Shamiko is actively hiding root access
}

// Individual detection methods
boolean behaviorDetected = shamiko.detectShamikoByBehavior();
boolean memoryDetected = shamiko.detectShamikoByMemorySignatures();
boolean fileDetected = shamiko.detectShamikoByFileAnalysis();
```

### 5. Native Detection

```java
// Simple native detection
boolean rootedNative = NativeRootDetection.performNativeDetection();

// Detailed native detection
NativeRootDetection.DetectionResult result = 
    NativeRootDetection.performDetailedNativeDetection();

if (result.nativeLibraryError) {
    Log.w("Security", "Native library error: " + result.errorMessage);
} else {
    Log.d("Security", "Native detection results: " + result.toString());
    
    if (result.overallResult) {
        Log.w("Security", "Native detection triggered");
        // Handle root detection
    }
}
```

## Security Best Practices

### 1. Layered Security Approach

```java
public class LayeredSecurityCheck {
    
    public static boolean isDeviceSecure(Context context) {
        // Layer 1: Basic checks
        if (basicSecurityCheck(context)) {
            return false; // Device compromised
        }
        
        // Layer 2: Advanced detection
        if (advancedSecurityCheck(context)) {
            return false; // Advanced threats detected
        }
        
        // Layer 3: Behavioral analysis
        if (behavioralSecurityCheck(context)) {
            return false; // Suspicious behavior detected
        }
        
        // Layer 4: Hardware validation
        if (hardwareSecurityCheck(context)) {
            return false; // Hardware integrity compromised
        }
        
        return true; // Device appears secure
    }
    
    private static boolean basicSecurityCheck(Context context) {
        AdvancedRootDetection detector = new AdvancedRootDetection(context);
        return detector.isDeviceCompromised();
    }
    
    private static boolean advancedSecurityCheck(Context context) {
        AntiBypassDetection antiBypass = new AntiBypassDetection(context);
        ShamikoSpecificDetection shamiko = new ShamikoSpecificDetection(context);
        
        return antiBypass.detectBypassAttempts() || shamiko.detectShamiko();
    }
    
    private static boolean behavioralSecurityCheck(Context context) {
        // Implement behavioral analysis
        return false;
    }
    
    private static boolean hardwareSecurityCheck(Context context) {
        IntegrityVerification verifier = new IntegrityVerification(context);
        return verifier.verifyDeviceIntegrity();
    }
}
```

### 2. Async Security Monitoring

```java
public class AsyncSecurityMonitor {
    private ExecutorService executorService;
    private Handler mainHandler;
    private Context context;
    
    public AsyncSecurityMonitor(Context context) {
        this.context = context;
        this.executorService = Executors.newSingleThreadExecutor();
        this.mainHandler = new Handler(Looper.getMainLooper());
    }
    
    public void startMonitoring() {
        executorService.execute(() -> {
            while (true) {
                try {
                    // Perform security check in background
                    boolean compromised = LayeredSecurityCheck.isDeviceSecure(context);
                    
                    if (compromised) {
                        // Post result to main thread
                        mainHandler.post(() -> handleSecurityBreach());
                        break;
                    }
                    
                    // Wait before next check
                    Thread.sleep(30000); // 30 seconds
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    Log.e("Security", "Monitor error", e);
                }
            }
        });
    }
    
    private void handleSecurityBreach() {
        Log.w("Security", "Security breach detected by async monitor");
        // Handle breach in main thread
    }
    
    public void stopMonitoring() {
        executorService.shutdown();
    }
}
```

### 3. Server-Side Validation

```java
public class ServerSecurityValidator {
    
    public void validateDeviceWithServer(Context context) {
        // Collect device information
        DeviceInfo deviceInfo = collectDeviceInfo(context);
        
        // Send to server for validation
        executorService.execute(() -> {
            try {
                ValidationResponse response = sendValidationRequest(deviceInfo);
                
                mainHandler.post(() -> {
                    if (!response.isDeviceSecure) {
                        handleServerValidationFailure(response);
                    }
                });
                
            } catch (Exception e) {
                Log.e("Security", "Server validation error", e);
            }
        });
    }
    
    private DeviceInfo collectDeviceInfo(Context context) {
        DeviceInfo info = new DeviceInfo();
        
        // Collect device fingerprint
        info.buildFingerprint = Build.FINGERPRINT;
        info.serialNumber = Build.SERIAL;
        info.androidId = Settings.Secure.getString(
            context.getContentResolver(), Settings.Secure.ANDROID_ID);
        
        // Collect security check results
        IntegratedSecurityManager security = new IntegratedSecurityManager(context);
        info.securityCheckResult = security.performComprehensiveSecurityCheck();
        
        // Collect hardware attestation
        IntegrityVerification verifier = new IntegrityVerification(context);
        info.hardwareAttestation = verifier.performHardwareAttestation();
        
        return info;
    }
    
    private ValidationResponse sendValidationRequest(DeviceInfo deviceInfo) {
        // Implement HTTP request to your validation server
        // Return server response
        return new ValidationResponse();
    }
    
    private static class DeviceInfo {
        String buildFingerprint;
        String serialNumber;
        String androidId;
        boolean securityCheckResult;
        boolean hardwareAttestation;
    }
    
    private static class ValidationResponse {
        boolean isDeviceSecure = true;
        String reason = "";
    }
}
```

## Testing and Validation

### 1. Running Test Suite

```java
public class SecurityTestRunner {
    
    public void runSecurityTests(Context context) {
        SecurityTestSuite testSuite = new SecurityTestSuite(context);
        
        // Run comprehensive test suite
        SecurityTestSuite.TestResults results = testSuite.runFullTestSuite();
        
        // Log results
        Log.i("SecurityTest", results.toString());
        
        // Check if tests passed
        if (results.overallPassed) {
            Log.i("SecurityTest", "All security tests passed!");
        } else {
            Log.w("SecurityTest", "Some security tests failed. Score: " + results.overallScore);
        }
        
        // Display results to user (in debug builds only)
        if (BuildConfig.DEBUG) {
            showTestResults(context, results);
        }
    }
    
    private void showTestResults(Context context, SecurityTestSuite.TestResults results) {
        new AlertDialog.Builder(context)
            .setTitle("Security Test Results")
            .setMessage(results.toString())
            .setPositiveButton("OK", null)
            .show();
    }
}
```

### 2. Performance Monitoring

```java
public class SecurityPerformanceMonitor {
    
    public void monitorPerformance(Context context) {
        long startTime = System.currentTimeMillis();
        
        IntegratedSecurityManager security = new IntegratedSecurityManager(context);
        boolean compromised = security.performComprehensiveSecurityCheck();
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        Log.d("Performance", "Security check completed in " + duration + "ms");
        Log.d("Performance", "Device compromised: " + compromised);
        
        // Alert if performance is poor
        if (duration > 1000) { // More than 1 second
            Log.w("Performance", "Security check took too long: " + duration + "ms");
        }
    }
}
```

## Integration with Existing Security

### 1. Certificate Pinning Integration

```java
public class SecureCertificatePinning {
    
    public boolean validateCertificateWithSecurityCheck(Context context, X509Certificate cert) {
        // First, check device security
        IntegratedSecurityManager security = new IntegratedSecurityManager(context);
        if (security.performComprehensiveSecurityCheck()) {
            Log.w("Security", "Rejecting certificate validation on compromised device");
            return false;
        }
        
        // Then validate certificate
        return validateCertificate(cert);
    }
    
    private boolean validateCertificate(X509Certificate cert) {
        // Implement certificate validation logic
        return true;
    }
}
```

### 2. Biometric Authentication Integration

```java
public class SecureBiometricAuth {
    
    public void authenticateWithSecurityCheck(Context context, BiometricCallback callback) {
        // Check device security before allowing biometric authentication
        IntegratedSecurityManager security = new IntegratedSecurityManager(context);
        
        if (security.performComprehensiveSecurityCheck()) {
            callback.onAuthenticationError("Device security compromised");
            return;
        }
        
        // Proceed with biometric authentication
        performBiometricAuthentication(callback);
    }
    
    private void performBiometricAuthentication(BiometricCallback callback) {
        // Implement biometric authentication
    }
    
    interface BiometricCallback {
        void onAuthenticationSuccess();
        void onAuthenticationError(String error);
    }
}
```

This comprehensive usage guide provides practical examples for integrating the root detection system into Android applications with various security requirements and architectures.