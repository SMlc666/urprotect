#include <jni.h>

JNIEXPORT jstring JNICALL
Java_com_example_urprotect_MainActivity_fixtureValue(JNIEnv *env, jclass ignored) {
    (void)ignored;
    return (*env)->NewStringUTF(env, "urprotect-fixture:android-ndk");
}
