/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct go_string { const char *str; long n; };
extern int awgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings, struct go_string xray_config);
extern void awgSetConfig(int handle, struct go_string settings, struct go_string xray_config);
extern void awgTurnOff(int handle);
extern int awgGetSocketV4(int handle);
extern int awgGetSocketV6(int handle);
extern char *awgGetConfig(int handle);
extern int64_t awgGetLastHandshake(int handle);
extern char *awgVersion();

JNIEXPORT jint JNICALL Java_org_amnezia_awg_backend_GoBackend_awgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings, jstring xray_config)
{
	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	const char *xray_config_str = (*env)->GetStringUTFChars(env, xray_config, 0);
	size_t xray_config_len = (*env)->GetStringUTFLength(env, xray_config);
	int ret = awgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	}, (struct go_string){
		.str = xray_config_str,
		.n = xray_config_len
	});
	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	(*env)->ReleaseStringUTFChars(env, xray_config, xray_config_str);
	return ret;
}

JNIEXPORT void JNICALL Java_org_amnezia_awg_backend_GoBackend_awgSetConfig(JNIEnv *env, jclass c, jint handle, jstring settings, jstring xray_config)
{
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	const char *xray_config_str = (*env)->GetStringUTFChars(env, xray_config, 0);
	size_t xray_config_len = (*env)->GetStringUTFLength(env, xray_config);
	awgSetConfig(handle, (struct go_string){
		.str = settings_str,
		.n = settings_len
	}, (struct go_string){
		.str = xray_config_str,
		.n = xray_config_len
	});
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	(*env)->ReleaseStringUTFChars(env, xray_config, xray_config_str);
}

JNIEXPORT void JNICALL Java_org_amnezia_awg_backend_GoBackend_awgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	awgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_awg_backend_GoBackend_awgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return awgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_awg_backend_GoBackend_awgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return awgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_org_amnezia_awg_backend_GoBackend_awgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = awgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_org_amnezia_awg_backend_GoBackend_awgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = awgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}

JNIEXPORT jlong JNICALL Java_org_amnezia_awg_backend_GoBackend_awgGetLastHandshake(JNIEnv *env, jclass c, jint handle)
{
	return awgGetLastHandshake(handle);
}
