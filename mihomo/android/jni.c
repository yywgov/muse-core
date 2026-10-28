//go:build android

// JNI entry points of libmusecompat.so for com.hiddify.hiddify.bg.CompatCore (Kotlin object with
// @JvmStatic external functions). Strings are copied in and out; the Go side never keeps a JNI
// reference.
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "_cgo_export.h"

static char *copy_jstring(JNIEnv *env, jstring s) {
	if (s == NULL) return strdup("");
	const char *c = (*env)->GetStringUTFChars(env, s, NULL);
	if (c == NULL) return strdup("");
	char *r = strdup(c);
	(*env)->ReleaseStringUTFChars(env, s, c);
	return r;
}

static jstring take_string(JNIEnv *env, char *s) {
	jstring out = (*env)->NewStringUTF(env, s == NULL ? "" : s);
	museCompatFree(s);
	return out;
}

JNIEXPORT jstring JNICALL Java_com_hiddify_hiddify_bg_CompatCore_nativeSetup(JNIEnv *env, jclass clazz, jstring base,
		jstring work, jstring temp, jstring listen, jstring secret, jboolean debug) {
	char *b = copy_jstring(env, base), *w = copy_jstring(env, work), *t = copy_jstring(env, temp);
	char *l = copy_jstring(env, listen), *s = copy_jstring(env, secret);
	char *err = museCompatSetup(b, w, t, l, s, debug ? 1 : 0);
	free(b); free(w); free(t); free(l); free(s);
	return take_string(env, err);
}

JNIEXPORT void JNICALL Java_com_hiddify_hiddify_bg_CompatCore_nativeSetTunFd(JNIEnv *env, jclass clazz, jint fd) {
	museCompatSetTunFd(fd);
}

JNIEXPORT void JNICALL Java_com_hiddify_hiddify_bg_CompatCore_nativeStop(JNIEnv *env, jclass clazz) {
	museCompatStop();
}

JNIEXPORT jstring JNICALL Java_com_hiddify_hiddify_bg_CompatCore_nativeVersion(JNIEnv *env, jclass clazz) {
	return take_string(env, museCompatVersion());
}
