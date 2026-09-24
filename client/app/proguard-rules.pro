# R8 rules for the TrafficWrapper client (release build type).

# Keep file/line info so crash stack traces stay readable (mapping.txt de-obfuscates names).
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# gomobile bindings (libs/transport.aar): the Go side calls back into these classes and their
# members by name through JNI (go.Seq, go.Universe, generated proxies), so nothing may be renamed
# or removed.
-keep class go.** { *; }
-keep class pro.trafficwrapper.go.** { *; }
-keep interface pro.trafficwrapper.go.** { *; }

# Any native method (and its declaring class name) must keep the JNI-visible name.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# WorkManager instantiates workers by the class name persisted in its database; keep the name
# stable across releases (work-runtime ships an equivalent rule, this is belt and braces).
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# apksig verifies update APK signatures; keep it intact - a mis-optimized verifier would break
# (or silently weaken) self-updates, which are the only way to ship fixes to public clients.
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# OkHttp optional TLS providers (not present on Android; OkHttp probes for them at runtime).
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-dontwarn okhttp3.internal.platform.**

# ZXing core has optional desktop-only helpers.
-dontwarn com.google.zxing.client.j2se.**

# Strip verbose/debug logging from release builds (arguments are dropped too when unused).
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}
