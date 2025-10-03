# ProGuard configuration for Android Root Detection
# This file contains security-focused obfuscation rules

# Keep main security classes but obfuscate methods
-keep class com.yourpackage.security.IntegratedSecurityManager {
    public <init>(android.content.Context);
    public <init>(android.content.Context, com.yourpackage.security.IntegratedSecurityManager$SecurityConfig);
    public boolean performComprehensiveSecurityCheck();
}

# Obfuscate all detection classes and methods
-obfuscatecode class com.yourpackage.security.AdvancedRootDetection
-obfuscatecode class com.yourpackage.security.AntiBypassDetection  
-obfuscatecode class com.yourpackage.security.IntegrityVerification
-obfuscatecode class com.yourpackage.security.ShamikoSpecificDetection

# Keep native method signatures but obfuscate class names
-keepclasseswithmembers class * {
    native <methods>;
}

# Obfuscate security-related strings
-adaptresourcefilenames **.properties
-adaptresourcefilecontents **.properties,META-INF/MANIFEST.MF

# Remove debug logging
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}

# String encryption (requires additional plugin)
-obfuscatecode class * {
    java.lang.String *;
}

# Control flow obfuscation
-repackageclasses 'o'
-allowaccessmodification
-mergeinterfacesaggressively
-overloadaggressively

# Advanced obfuscation
-adaptclassstrings
-adaptresourcefilenames
-adaptresourcefilecontents

# Security-specific rules
-keep class com.yourpackage.security.**$SecurityBreach { *; }
-keep class com.yourpackage.security.**$SecurityConfig { *; }
-keep interface com.yourpackage.security.**$SecurityCallback { *; }

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Anti-tampering
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses
-keepattributes EnclosingMethod

# Reflection protection
-keepclassmembers class * {
    @androidx.annotation.Keep <methods>;
    @androidx.annotation.Keep <fields>;
    @androidx.annotation.Keep <init>(...);
}

# Native library protection
-keepclassmembers class * {
    static {
        java.lang.System.loadLibrary(***); 
    }
}

# Remove parameter names and line numbers
-keepparameternames
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Additional security measures
-dontskipnonpubliclibraryclasses
-dontskipnonpubliclibraryclassmembers

# Optimize aggressively
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5
-allowaccessmodification
-dontpreverify

# Remove unused code
-dontwarn **
-ignorewarnings