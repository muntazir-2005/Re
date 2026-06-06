#ifndef ANTIBAN_ADVANCED_H
#define ANTIBAN_ADVANCED_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <DeviceCheck/DeviceCheck.h>
#import <CommonCrypto/CommonCrypto.h>

// ============================================================================
// Advanced AntiBan Detection & Bypass System
// ============================================================================

typedef enum {
    AntiBanLevelBasic = 0,
    AntiBanLevelIntermediate = 1,
    AntiBanLevelAdvanced = 2,
    AntiBanLevelParanoid = 3,
    AntiBanLevelMilitaryGrade = 4
} AntiBanLevel;

typedef struct {
    BOOL fingerprint_enabled;
    BOOL device_attestation_enabled;
    BOOL api_signature_check_enabled;
    BOOL suspicious_method_detection;
    BOOL integrity_check_enabled;
    BOOL certificate_pinning_enabled;
    BOOL safetynet_check_enabled;
    BOOL devicecheck_enabled;
    BOOL memory_check_enabled;
    BOOL process_list_check_enabled;
    BOOL hook_detection_enabled;
    BOOL network_inspection_enabled;
} AntiBanConfig;

// Core functions
void init_antiban_hooks(AntiBanLevel level);
void disable_antiban_detection(void);
void spoof_device_info(void);
void patch_integrity_checks(void);
void bypass_certificate_pinning(void);
void hook_app_attest_service(void);
void hook_device_check_service(void);
void init_advanced_fingerprinting(void);
void hook_all_antiban_vectors(void);

#endif // ANTIBAN_ADVANCED_H
