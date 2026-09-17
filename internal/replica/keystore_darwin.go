//go:build darwin

package replica

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/VortexNYC/veil/internal/crypto"
)

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static CFMutableDictionaryRef veil_replica_query(void) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, CFSTR("nyc.veil.fill"));
	CFDictionarySetValue(q, kSecAttrAccount, CFSTR("replica"));
	return q;
}

static int veil_replica_get(void *out, int cap) {
	CFMutableDictionaryRef q = veil_replica_query();
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st == errSecItemNotFound) {
		return 0;
	}
	if (st != errSecSuccess || result == NULL) {
		return -1;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex n = CFDataGetLength(data);
	if (n <= 0 || n > cap) {
		CFRelease(result);
		return -1;
	}
	memcpy(out, CFDataGetBytePtr(data), (size_t)n);
	CFRelease(result);
	return (int)n;
}

static int veil_replica_put(const void *in, int n) {
	CFMutableDictionaryRef q = veil_replica_query();
	SecItemDelete(q);
	CFDataRef data = CFDataCreate(NULL, in, n);
	if (data == NULL) {
		CFRelease(q);
		return -1;
	}
	CFDictionarySetValue(q, kSecValueData, data);
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		kSecAccessControlUserPresence,
		NULL);
	if (ac == NULL) {
		CFRelease(data);
		CFRelease(q);
		return -1;
	}
	CFDictionarySetValue(q, kSecAttrAccessControl, ac);
	CFRelease(ac);
	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(data);
	CFRelease(q);
	return st == errSecSuccess ? 0 : -1;
}
*/
import "C"

type keychain struct{}

func Platform() KeyStore {
	if os.Getenv("VEIL_REPLICA_KEYSTORE") == "mem" {
		return Mem()
	}
	return keychain{}
}

func (keychain) Get() ([]byte, error) {
	buf := make([]byte, crypto.KeySize)
	n := C.veil_replica_get(unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if n == 0 {
		return nil, ErrNotFound
	}
	if int(n) != crypto.KeySize {
		return nil, fmt.Errorf("replica: keychain")
	}
	return buf, nil
}

func (keychain) Put(key []byte) error {
	if len(key) != crypto.KeySize {
		return fmt.Errorf("replica: key")
	}
	if C.veil_replica_put(unsafe.Pointer(&key[0]), C.int(len(key))) != 0 {
		return fmt.Errorf("replica: keychain put")
	}
	return nil
}
