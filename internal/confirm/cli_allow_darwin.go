//go:build darwin

package confirm

import (
	"unsafe"
)

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static CFMutableDictionaryRef veil_cli_query(const char *bundle) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, CFSTR("nyc.veil.cli"));
	CFStringRef acc = CFStringCreateWithCString(NULL, bundle, kCFStringEncodingUTF8);
	CFDictionarySetValue(q, kSecAttrAccount, acc);
	CFRelease(acc);
	return q;
}

static int veil_cli_get(const char *bundle) {
	CFMutableDictionaryRef q = veil_cli_query(bundle);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) {
		return 0;
	}
	if (result != NULL) {
		CFRelease(result);
	}
	return 1;
}

static int veil_cli_put(const char *bundle) {
	CFMutableDictionaryRef q = veil_cli_query(bundle);
	SecItemDelete(q);
	const unsigned char one = '1';
	CFDataRef data = CFDataCreate(NULL, &one, 1);
	if (data == NULL) {
		CFRelease(q);
		return -1;
	}
	CFDictionarySetValue(q, kSecValueData, data);
	CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(data);
	CFRelease(q);
	return st == errSecSuccess ? 0 : -1;
}
*/
import "C"

func cliAllowed(bundle string) bool {
	if bundle == "" {
		return false
	}
	cs := C.CString(bundle)
	defer C.free(unsafe.Pointer(cs))
	return C.veil_cli_get(cs) == 1
}

func cliRemember(bundle string) {
	if bundle == "" {
		return
	}
	cs := C.CString(bundle)
	defer C.free(unsafe.Pointer(cs))
	_ = C.veil_cli_put(cs)
}
