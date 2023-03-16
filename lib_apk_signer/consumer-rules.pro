# 不混淆某个包所有的类
-keep class com.android.apksig.** { *; }
-keep class com.android.apksigner.** { *; }
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }