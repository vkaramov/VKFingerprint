//
//  VKKeychain.swift
//  SwiftyTouchId
//
//  Created by Viacheslav Karamov on 01.10.15.
//  Copyright © 2015 Viacheslav Karamov. All rights reserved.
//

import Foundation
import Security

/// Simple Keychain Swift wrapper for iOS
open class VKKeychain : NSObject
{
    /// Human-readable label
    open var label : NSString = ""
    /// Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    open var accessGroup : NSString? = nil
    /// Service associated with this item. See Security.kSecAttrService constant for details
    open var service : NSString = Bundle.main.bundleIdentifier as NSString? ?? "default_service"
    /// Should touchID be used. False by dafault. This property is ignored when running in Simulator
    open var touchIdEnabled = false
    
    /**
    Convenience intializer
    
    - parameter lb:             Human-readable label
    - parameter touchIdEnabled: Should touchID be used. This variable is ignored when running in Simulator
    - parameter accessGroup:    Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    - parameter service:        Service associated with this item. See Security.kSecAttrService constant for details. If you pass nil, NSBundle.mainBundle().bundleIdentifier value is used instead.
    */
    public convenience init(label lb:NSString, touchIdEnabled:Bool, accessGroup:NSString?, service:NSString?)
    {
        self.init()
        self.label = lb
        self.accessGroup = accessGroup
       
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            self.touchIdEnabled = touchIdEnabled
        #endif
        
        if let service = service
        {
            self.service = service
        }
    }
    
    /**
    Reads data from the Keychain
    
    - parameter key: Key to read
    
    - throws: NSError on error
    
    - returns: Corresponding value from the Keychain
    */
    open func get(_ key:NSString) throws -> Data?
    {
        var query = try self.query(key)
        query[kSecReturnData as String] = true as AnyObject?
        
        var result: AnyObject?
        let status = withUnsafeMutablePointer(to: &result) { SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0)) }
        
        switch status
        {
        case errSecSuccess:
            guard let data = result as? Data else
            {
                return nil
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw securityError(status: status)
        }
    }
    
    /**
    Writes data to the Keychain for the key specified
    
    - parameter value: Value to write
    - parameter key:   Key to store value for
    
    - throws: NSError on error
    */
    open func set(_ value: Data, key: NSString) throws
    {
        try remove(key)
        
        var query = try self.query(key)
        query[kSecValueData as String] = value as AnyObject?
        if #available(iOS 9.0, *)
        {
            query[kSecUseAuthenticationUI as String] = kCFBooleanFalse
        }
        else
        {
            query[kSecUseNoAuthenticationUI as String] = kCFBooleanTrue
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess
        {
            throw securityError(status: status)
        }
        
        if (touchIdEnabled)
        {
            try setValidationValue()
        }
    }
    
    /**
    Updates data in the Keychain for the key specified
    
    - parameter value: New value
    - parameter key:   Key to store value for
    
    - throws: NSError on error
    */
    open func update(_ value : Data, key : NSString) throws
    {
        let query = try self.query(key)
        let changes = [kSecValueData as String : value]
        
        let status = SecItemUpdate(query as CFDictionary, changes as CFDictionary)
        if status != errSecSuccess
        {
            throw securityError(status: status)
        }
    }

    /**
    Removes value from the keychain using the key provided
    
    - parameter key: Key to remove value for
    
    - throws: NSError on error
    */
    open func remove(_ key: NSString) throws
    {
        let query = [kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String : service,
            kSecAttrAccount as String : key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound
        {
            throw securityError(status: status)
        }
        
        try resetValidationValue()
    }

    /**
    Checks if validation value is present. The users can disable and enable touch ID while your App is running, so
    all touchID-protected data would be lost. There's no way to check this case directly, so the library writes special verification value to the keychain allowing the client to check if the user has disabled TouchID and then enabled
    
    - returns: Returns true if validation value is present
    */
    open func hasValidationValue() -> Bool
    {
        let query = [kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : validationService,
            kSecReturnData as String : true
        ] as [String : Any]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    fileprivate var accessControl:SecAccessControl?
    fileprivate var validationService : String
    {
        return service as String + "_validation";
    }
}

//MARK: -
//MARK: Private methods
//MARK: -
private extension VKKeychain
{
    func setValidationValue() throws
    {
        let value:String = "validation"
        var query = [kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : validationService,
            kSecValueData as String : value.data(using: String.Encoding.utf8)!,
            kSecAttrAccessible as String : kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ] as [String : Any]
        if #available(iOS 9.0, *)
        {
            query[kSecUseAuthenticationUI as String] = kCFBooleanFalse
        }
        else
        {
            query[kSecUseNoAuthenticationUI as String] = kCFBooleanTrue
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess
        {
            throw securityError(status: status)
        }
    }
    
    func resetValidationValue() throws
    {
        let query = [kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : validationService] as [String : Any]
        let status = SecItemDelete(query as CFDictionary)
        if ((status != errSecSuccess) && (status != errSecItemNotFound))
        {
            throw securityError(status: status)
        }
    }
    
    func query(_ key : NSString, value:Data? = nil) throws -> [String: AnyObject]
    {
        var query:[String:AnyObject] = [kSecClass as String:kSecClassGenericPassword,
                                        kSecAttrLabel as String   : label,
                                        kSecAttrService as String : service,
                                        kSecAttrAccount as String : key
        ]
        
        #if !TARGET_IPHONE_SIMULATOR
            query[kSecAttrAccessGroup as String] = accessGroup
        #endif
        
        if (touchIdEnabled)
        {
            var error: Unmanaged<CFError>?
            if (accessControl == nil)
            {
                accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &error)
            }
            
            guard let accessControl = accessControl else
            {
                if let err = error?.takeUnretainedValue()
                {
                    let errorToThrow = NSError(domain: CFErrorGetDomain(err) as String, code: CFErrorGetCode(err), userInfo: CFErrorCopyUserInfo(err) as! [AnyHashable : Any]?)
                    throw errorToThrow
                }
                else
                {
                    let errorToThrow = NSError(domain: "KeychainDomain", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create access control object"])
                    throw errorToThrow
                }
            }
            
            query[kSecAttrAccessControl as String] = accessControl
        }
        return query
    }
    
    class func securityError(status: OSStatus) -> NSError
    {
        var message = NSLocalizedString("Unknown error", comment: "")
        
        switch (status)
        {
        case errSecDuplicateItem:
            message = NSLocalizedString("Such keychain item is already exists in the keychain", comment: "")
            break
            
        case errSecItemNotFound:
            message = NSLocalizedString("Can't find item in the keychain", comment: "")
            break
            
        case errSecAuthFailed:
            message = NSLocalizedString("Authentication failed", comment: "")
            break
            
        case errSecParam:
            message = NSLocalizedString("Parameters passed to a function were not valid", comment: "")
            break
            
        default:
            break
            
        }
        
        let error = NSError(domain: "KeychainDomain", code: Int(status), userInfo: [NSLocalizedDescriptionKey: message])
        print("OSStatus error:[\(error.code)] \(error.localizedDescription)")
        
        return error
    }
    
    func securityError(status: OSStatus) -> NSError
    {
        return type(of: self).securityError(status: status)
    }
}
