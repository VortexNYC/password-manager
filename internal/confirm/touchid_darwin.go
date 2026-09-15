//go:build darwin

package confirm

import (
	"fmt"
	"unsafe"
)

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>

static int pwm_touchid(const char *reason) {
	__block int ok = 0;
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	LAContext *ctx = [[LAContext alloc] init];
	NSError *authError = nil;
	if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
		return 0;
	}
	NSString *why = [NSString stringWithUTF8String:reason];
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
		localizedReason:why
				  reply:^(BOOL success, NSError *error) {
					ok = success ? 1 : 0;
					dispatch_semaphore_signal(sema);
				  }];
	if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC)) != 0) {
		return 0;
	}
	return ok;
}
*/
import "C"

const touchIDAvailable = true

// TouchID is device owner auth (biometrics, else Mac password). Cancel fails closed.
func TouchID(reason string) error {
	if reason == "" {
		reason = "Veil wants to fill a saved sign-in"
	}
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	if C.pwm_touchid(cr) != 1 {
		return fmt.Errorf("fill: touch id declined")
	}
	return nil
}
