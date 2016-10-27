//
//  VKFingerprint.swift
//  SwiftyTouchId
//
//  Created by Viacheslav Karamov on 02.10.15.
//  Copyright © 2015 Viacheslav Karamov. All rights reserved.
//

import Foundation
import LocalAuthentication

public typealias VKKeychainCompletion = (Bool) -> Void;
public typealias VKKeychainCompletionWithValue = (_ error : NSError?, _ value : Data?) -> Void;
public typealias VKKeychainCompletionWithString = (_ error : NSError?, _ value : String?) -> Void;

/**
Fingerprint scanner availablity state

- Unavailable: Fingerprint is not supported by the device
- Available:   Fingerprint available but not configured
- Configured:  Fingerprint available and configured
*/
public enum VKFingerprintState
{
    case unavailable, available, configured;
}

/// Simple Fingerprint Swift wrapper for iOS
open class VKFingerprint : NSObject
{
    /// Human-readable label
    open var label : String = ""
    /// Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    open var accessGroup : String? = nil
    /// Service associated with this item. See Security.kSecAttrService constant for details
    open var service : String = Bundle.main.bundleIdentifier ?? "default_service"
    
    /**
    Convenience intializer
    
    - parameter lb:             Human-readable label
    - parameter touchIdEnabled: Should touchID be used. This variable is ignored when running in Simulator
    - parameter accessGroup:    Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    - parameter service:        Service associated with this item. See Security.kSecAttrService constant for details. If you pass nil, NSBundle.mainBundle().bundleIdentifier value is used instead.
    */
    public convenience init(label lb:String, touchIdEnabled:Bool, accessGroup:String?, service:String?)
    {
        self.init();
        self.label = lb
        self.accessGroup = accessGroup
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            self.touchIdEnabled = (.configured == availabilityState) && touchIdEnabled
        #endif
        
        if let service = service
        {
            self.service = service
        }
    }
    
    /// Returns Fingerprint scanner availability state
    open var availabilityState : VKFingerprintState
    {
        let context = LAContext();
        var error:NSError?
        let evaluated = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if let error = error
        {
            NSLog("Failed to initialize fingerprint scanner: %@", error);
            let laError = LAError.Code(rawValue: error.code)!
            switch laError
            {
            case .touchIDNotAvailable, .passcodeNotSet:
                return .unavailable
            default:
                // In iOS 8.0 & 8.1 .PasscodeNotSet might be returned for the devices which doesn't support TouchID
                // To not compare with the list of devices, I've just set minimum supported version to 8.2. Profit!
                return .available
            }
        }
        return evaluated ? .configured :.unavailable
    }
    
    /**
    Stores value to the Keychain using the key spacified
    
    - parameter value:      Value to store
    - parameter key:        Key to store value for
    - parameter completion: Optional completion block. Will be dispatched to the main thread
    */
    open func setValue(_ value: Data, forKey key: String, completion:VKKeychainCompletion?)
    {
        let keychain = VKKeychain(label: label, touchIdEnabled: (.configured == availabilityState) && touchIdEnabled, accessGroup: accessGroup, service: service);
        
        queue.async { () -> Void in
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
                DispatchQueue.main.async(execute: { () -> Void in
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
    open func setStringValue(_ value : String, forKey key : String, completion : VKKeychainCompletion?)
    {
        if let data = value.data(using: .utf8)
        {
            setValue(data, forKey: key, completion: completion);
        }
    }
    
    /**
    Reads data from the Keychain using the key specified. Users will be prompted to hold their fingers to the touchID sensor if device has it.
    
    - parameter key:        Key to read value for
    - parameter completion: Completion block. Will be dispatched to the main thread
    */
    open func getValue(forKey key: String, completion:@escaping VKKeychainCompletionWithValue)
    {
        let keychain = VKKeychain(label: label, touchIdEnabled: (.configured == availabilityState) && touchIdEnabled, accessGroup: accessGroup, service: service);
        
        queue.async { () -> Void in
            var data:Data? = nil;
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
            DispatchQueue.main.async(execute: { () -> Void in
                completion(error, data);
            })
        }
    }
    
    /**
    Reads string from the Keychain using the key specified. Users will be prompted to hold their fingers to the touchID sensor if device has it.
    
    - parameter key:        Key to read value for
    - parameter completion: Completion block. Will be dispatched to the main thread
    */
    open func getString(forKey key: String, completion:@escaping VKKeychainCompletionWithString)
    {
        getValue(forKey: key) { (error:NSError?, value:Data?) -> Void in
            let stringValue = value != nil ? String(data: value!, encoding: .utf8) : nil;
            completion(error, stringValue);
        };
    }
    
    /**
    Removes value from the keychain using the key provided.
    
    - parameter key:        Key to remove value for
    - parameter completion: Optional completion block. Will be dispatched to the main thread
    */
    open func resetValue(forKey key:NSString, completion:VKKeychainCompletion?)
    {
        let keychain = VKKeychain();
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            keychain.touchIdEnabled = (.configured == availabilityState) && touchIdEnabled;
        #endif
        
        keychain.service = service;
        
        queue.async { () -> Void in
            var success = true;
            do
            {
                try keychain.remove(key as String);
            }
            catch let error as NSError
            {
                NSLog("Failed to reset keychain value: ", error);
                success = false;
            }
            if let completion = completion
            {
                DispatchQueue.main.async(execute: { () -> Void in
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
    open func validateValue(_ completion:@escaping VKKeychainCompletion)
    {
        let keychain = VKKeychain();
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            keychain.touchIdEnabled = (.configured == availabilityState) && touchIdEnabled;
        #endif
        
        queue.async { () -> Void in
            let valid = keychain.hasValidationValue()
            DispatchQueue.main.async(execute: { () -> Void in
                completion(valid);
            })
        }
    }
    
    fileprivate let queue = DispatchQueue(label: "VKFingerprintSerialQueue", attributes: []);
    fileprivate var touchIdEnabled = false;

}
