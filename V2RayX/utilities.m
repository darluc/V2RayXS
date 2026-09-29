//
//  utilities.m
//  V2RayX
//
//

#import "utilities.h"

static NSString* trimmedStringValue(id value) {
    if (![value isKindOfClass:[NSString class]]) {
        return @"";
    }
    return [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

NSUInteger searchInArray(NSString* str, NSArray* array) {
    if ([str isKindOfClass:[NSString class]]) {
        NSUInteger index = 0;
        for (NSString* s in array) {
            if ([s isKindOfClass:[NSString class]] && [s isEqualToString:str]) {
                return index;
            }
            index += 1;
        }
    }
    return 0;
}

static NSDictionary* networkTypeToSettingKey(void) {
    return @{
        @"tcp": @"tcpSettings",
        @"kcp": @"kcpSettings",
        @"ws": @"wsSettings",
        @"http": @"httpSettings",
        @"quic": @"quicSettings",
        @"grpc": @"grpcSettings",
        @"httpupgrade": @"httpupgradeSettings",
        @"xhttp": @"xhttpSettings",
    };
}

NSMutableDictionary* normalizedStreamSettingsForXray(NSDictionary* streamSettings) {
    NSMutableDictionary* normalized = [streamSettings isKindOfClass:[NSDictionary class]] ? [streamSettings mutableDeepCopy] : [[NSMutableDictionary alloc] init];

    NSMutableDictionary* wsSettings = [normalized[@"wsSettings"] isKindOfClass:[NSDictionary class]] ? [normalized[@"wsSettings"] mutableDeepCopy] : nil;
    if (wsSettings != nil) {
        NSMutableDictionary* headers = [wsSettings[@"headers"] isKindOfClass:[NSDictionary class]] ? [wsSettings[@"headers"] mutableDeepCopy] : nil;
        NSString* host = [wsSettings[@"host"] isKindOfClass:[NSString class]] ? wsSettings[@"host"] : @"";
        if (host.length == 0 && [headers[@"Host"] isKindOfClass:[NSString class]]) {
            wsSettings[@"host"] = headers[@"Host"];
        }
        normalized[@"wsSettings"] = wsSettings;
    }

    NSArray* tlsSettingNames = @[@"tlsSettings", @"xtlsSettings", @"realitySettings"];
    for (NSString* settingName in tlsSettingNames) {
        NSMutableDictionary* settings = [normalized[settingName] isKindOfClass:[NSDictionary class]] ? [normalized[settingName] mutableDeepCopy] : nil;
        if (settings == nil) {
            continue;
        }
        NSArray* stringKeys = @[@"pinnedPeerCertSha256", @"verifyPeerCertByName", @"echConfigList", @"mldsa65Verify", @"password", @"publicKey", @"shortId", @"spiderX"];
        for (NSString* key in stringKeys) {
            NSString* value = trimmedStringValue(settings[key]);
            if (value.length > 0) {
                settings[key] = value;
            } else {
                [settings removeObjectForKey:key];
            }
        }
        if ([settingName isEqualToString:@"realitySettings"] && settings[@"password"] == nil && settings[@"publicKey"] != nil) {
            settings[@"password"] = settings[@"publicKey"];
        }
        normalized[settingName] = settings;
    }

    // Remove transport settings that don't match the selected network type.
    // At runtime the streamSettings dictionary already has the "network" key set
    // by outboundProfile.  In the storage path (where "network" is absent) we
    // keep all transport settings so the UI can still display them.
    NSString* network = [normalized[@"network"] isKindOfClass:[NSString class]] ? normalized[@"network"] : nil;
    if (network != nil) {
        NSDictionary* keyMap = networkTypeToSettingKey();
        NSString* activeKey = keyMap[network];
        for (NSString* key in [keyMap allValues]) {
            if (![key isEqualToString:activeKey] && normalized[key] != nil) {
                [normalized removeObjectForKey:key];
            }
        }
    }

    // Clean up TLS / XTLS / Reality settings based on the security field.
    // Only keep the settings that match the chosen security type.
    NSString* security = [normalized[@"security"] isKindOfClass:[NSString class]] ? normalized[@"security"] : @"none";
    if ([security isEqualToString:@"tls"]) {
        [normalized removeObjectForKey:@"xtlsSettings"];
        [normalized removeObjectForKey:@"realitySettings"];
    } else if ([security isEqualToString:@"xtls"]) {
        [normalized removeObjectForKey:@"tlsSettings"];
        [normalized removeObjectForKey:@"realitySettings"];
    } else if ([security isEqualToString:@"reality"]) {
        [normalized removeObjectForKey:@"tlsSettings"];
        [normalized removeObjectForKey:@"xtlsSettings"];
    } else {
        // security is "none" or any other value — remove all TLS/XTLS/Reality settings
        [normalized removeObjectForKey:@"tlsSettings"];
        [normalized removeObjectForKey:@"xtlsSettings"];
        [normalized removeObjectForKey:@"realitySettings"];
    }

    return normalized;
}

NSMutableDictionary* normalizedStreamSettingsForXrayForCore(NSDictionary* streamSettings, BOOL rejectsTLSAllowInsecure) {
    NSMutableDictionary* normalized = normalizedStreamSettingsForXray(streamSettings);

    // xray-core removed the mKCP "header" and "seed" fields; providing either one
    // makes the core fail to build the config.  They are only dropped from the
    // generated config, so profiles created by older versions of the app keep
    // their values instead of being silently rewritten on the next save.
    NSMutableDictionary* kcpSettings = [normalized[@"kcpSettings"] isKindOfClass:[NSDictionary class]] ? [normalized[@"kcpSettings"] mutableDeepCopy] : nil;
    if (kcpSettings != nil) {
        [kcpSettings removeObjectForKey:@"header"];
        [kcpSettings removeObjectForKey:@"seed"];
        normalized[@"kcpSettings"] = kcpSettings;
    }

    NSArray* tlsSettingNames = @[@"tlsSettings", @"xtlsSettings"];
    for (NSString* settingName in tlsSettingNames) {
        NSMutableDictionary* tlsSettings = [normalized[settingName] isKindOfClass:[NSDictionary class]] ? [normalized[settingName] mutableDeepCopy] : nil;
        if (tlsSettings != nil) {
            NSString* manualPin = trimmedStringValue(tlsSettings[@"pinnedPeerCertSha256"]);
            if (manualPin.length > 0) {
                tlsSettings[@"pinnedPeerCertSha256"] = manualPin;
            } else {
                [tlsSettings removeObjectForKey:@"pinnedPeerCertSha256"];
            }
            [tlsSettings removeObjectForKey:@"autoPinnedPeerCertSha256"];
            [tlsSettings removeObjectForKey:@"pinnedPeerCertSha256Source"];
            NSString* verifyPeerCertByName = trimmedStringValue(tlsSettings[@"verifyPeerCertByName"]);
            if (verifyPeerCertByName.length > 0) {
                tlsSettings[@"verifyPeerCertByName"] = verifyPeerCertByName;
            } else {
                [tlsSettings removeObjectForKey:@"verifyPeerCertByName"];
            }
            normalized[settingName] = tlsSettings;
        }
    }

    return normalized;
}
