//
//  VKFingerprint.swift
//  SwiftyTouchId
//
//  Created by Viacheslav Karamov on 02.10.15.
//  Copyright © 2015 Viacheslav Karamov. All rights reserved.
//

import Foundation
import LocalAuthentication

public typealias VKKeychainCompletion = Bool -> Void;
public typealias VKKeychainCompletionWithValue = (error : NSError?, value : NSData?) -> Void;
public typealias VKKeychainCompletionWithString = (error : NSError?, value : NSString?) -> Void;

/**
Fingerprint scanner availablity state

- Unavailable: Fingerprint is not supported by the device
- Available:   Fingerprint available but not configured
- Configured:  Fingerprint available and configured
*/
public enum VKFingerprintState
{
    case Unavailable, Available, Configured;
}

/// Simple Fingerprint Swift wrapper for iOS
public class VKFingerprint : NSObject
{
    /// Human-readable label
    public var label : NSString = ""
    /// Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    public var accessGroup : NSString? = nil
    /// Service associated with this item. See Security.kSecAttrService constant for details
    public var service : NSString = NSBundle.mainBundle().bundleIdentifier ?? "default_service"
    
    /**
    Convenience intializer
    
    - parameter lb:             Human-readable label
    - parameter touchIdEnabled: Should touchID be used. This variable is ignored when running in Simulator
    - parameter accessGroup:    Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    - parameter service:        Service associated with this item. See Security.kSecAttrService constant for details. If you pass nil, NSBundle.mainBundle().bundleIdentifier value is used instead.
    */
    public convenience init(label lb:NSString, touchIdEnabled:Bool, accessGroup:NSString?, service:NSString?)
    {
        self.init();
        self.label = lb
        self.accessGroup = accessGroup
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            self.touchIdEnabled = (.Configured == availabilityState) && touchIdEnabled
        #endif
        
        if let service = service
        {
            self.service = service
        }
    }
    
    /// Returns Fingerprint scanner availability state
    public var availabilityState : VKFingerprintState
    {
        let context = LAContext();
        var error:NSError?
        let evaluated = context.canEvaluatePolicy(.DeviceOwnerAuthenticationWithBiometrics, error: &error)
        if let error = error
        {
            NSLog("Failed to initialize fingerprint scanner: %@", error);
            let laError = LAError(rawValue: error.code)!
            switch laError
            {
            case .TouchIDNotAvailable, .PasscodeNotSet:
                return .Unavailable
            default:
                // In iOS 8.0 & 8.1 .PasscodeNotSet might be returned for the devices which doesn't support TouchID
                // To not compare with the list of devices, I've just set minimum supported version to 8.2. Profit!
                return .Available
            }
        }
        return evaluated ? .Configured :.Unavailable
    }
    
    /**
    Stores value to the Keychain using the key spacified
    
    - parameter value:      Value to store
    - parameter key:        Key to store value for
    - parameter completion: Optional completion block. Will be dispatched to the main thread
    */
    public func setValue(value: NSData, forKey key: NSString, completion:VKKeychainCompletion?)
    {
        let keychain = VKKeychain(label: label, touchIdEnabled: (.Configured == availabilityState) && touchIdEnabled, accessGroup: accessGroup, service: service);
        
        dispatch_async(queue) { () -> Void in
            var success = true;
            do
            {
                try keychain.set(value, key: key);
            }
            catch let error as NSError
            {
                NSLog("Failed to add value to keychain: ", error);
                success = false;
            }
            if let completion = completion
            {
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    completion(success);
                })
            }
        }
    }
    
    /**
    Stores string to the Keychain using the key spacified
    
    - parameter value:      String to store
    - parameter key:        Key to store value for
    - parameter completion: Optional completion block. Will be dispatched to the main thread
    */
    public func setStringValue(value : NSString, forKey key : NSString, completion : VKKeychainCompletion?)
    {
        let data = value.dataUsingEncoding(NSUTF8StringEncoding)!;
        setValue(data, forKey: key, completion: completion);
    }
    
    /**
    Reads data from the Keychain using the key specified. Users will be prompted to hold their fingers to the touchID sensor if device has it.
    
    - parameter key:        Key to read value for
    - parameter completion: Completion block. Will be dispatched to the main thread
    */
    public func getValue(forKey key: NSString, completion:VKKeychainCompletionWithValue)
    {
        let keychain = VKKeychain(label: label, touchIdEnabled: (.Configured == availabilityState) && touchIdEnabled, accessGroup: accessGroup, service: service);
        
        dispatch_async(queue) { () -> Void in
            var data:NSData? = nil;
            var error:NSError? = nil;
            do
            {
                data = try keychain.get(key);
            }
            catch let err as NSError
            {
                error = err;
                NSLog("Failed to get keychain value: ", err);
            }
            dispatch_async(dispatch_get_main_queue(), { () -> Void in
                completion(error: error, value: data);
            })
        }
    }
    
    /**
    Reads string from the Keychain using the key specified. Users will be prompted to hold their fingers to the touchID sensor if device has it.
    
    - parameter key:        Key to read value for
    - parameter completion: Completion block. Will be dispatched to the main thread
    */
    public func getString(forKey key: NSString, completion:VKKeychainCompletionWithString)
    {
        getValue(forKey: key) { (error:NSError?, value:NSData?) -> Void in
            let stringValue = value != nil ? NSString(data: value!, encoding: NSUTF8StringEncoding) : nil;
            completion(error: error, value: stringValue);
        };
    }
    
    /**
    Removes value from the keychain using the key provided.
    
    - parameter key:        Key to remove value for
    - parameter completion: Optional completion block. Will be dispatched to the main thread
    */
    public func resetValue(forKey key:NSString, completion:VKKeychainCompletion?)
    {
        let keychain = VKKeychain();
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            keychain.touchIdEnabled = (.Configured == availabilityState) && touchIdEnabled;
        #endif
        
        keychain.service = service;
        
        dispatch_async(queue) { () -> Void in
            var success = true;
            do
            {
                try keychain.remove(key);
            }
            catch let error as NSError
            {
                NSLog("Failed to reset keychain value: ", error);
                success = false;
            }
            if let completion = completion
            {
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    completion(success);
                })
            }
        }
    }
    
    /**
    Checks if validation value is present. The users can disable and enable touch ID while your App is running, so
    all touchID-protected data would be lost. There's no way to check this case directly, so the library writes special verification value to the keychain allowing the client to check if the user has disabled TouchID and then enabled
    
    - parameter completion: Completion block. Will be dispatched to the main thread
    */
    public func validateValue(completion:VKKeychainCompletion)
    {
        let keychain = VKKeychain();
        keychain
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            keychain.touchIdEnabled = (.Configured == availabilityState) && touchIdEnabled;
        #endif
        
        dispatch_async(queue) { () -> Void in
            let valid = keychain.hasValidationValue()
            dispatch_async(dispatch_get_main_queue(), { () -> Void in
                completion(valid);
            })
        }
    }
    
    private let queue = dispatch_queue_create("VKFingerprintSerialQueue", DISPATCH_QUEUE_SERIAL);
    private var touchIdEnabled = false;

}
