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
public class VKKeychain : NSObject
{
    /// Human-readable label
    public var label : NSString = ""
    /// Access group. Access groups can be used to share keychain items among two or more applications. For applications to share a keychain item, the applications must have a common access group listed in their keychain-access-groups entitlement
    public var accessGroup : NSString? = nil
    /// Service associated with this item. See Security.kSecAttrService constant for details
    public var service : NSString = NSBundle.mainBundle().bundleIdentifier ?? "default_service"
    /// Should touchID be used. False by dafault. This property is ignored when running in Simulator
    public var touchIdEnabled = false
    
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
    public func get(key:NSString) throws -> NSData?
    {
        var query = try self.query(key)
        query[kSecReturnData as String] = true
        
        var result: AnyObject?
        let status = withUnsafeMutablePointer(&result) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
        
        switch status
        {
        case errSecSuccess:
            guard let data = result as? NSData else
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
    public func set(value: NSData, key: NSString) throws
    {
        try remove(key)
        
        var query = try self.query(key)
        query[kSecValueData as String] = value
        if #available(iOS 9.0, *)
        {
            query[kSecUseAuthenticationUI as String] = kCFBooleanFalse
        }
        else
        {
            query[kSecUseNoAuthenticationUI as String] = kCFBooleanTrue
        }
        
        let status = SecItemAdd(query, nil)
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
    public func update(value : NSData, key : NSString) throws
    {
        let query = try self.query(key)
        let changes = [kSecValueData as String : value]
        
        let status = SecItemUpdate(query, changes)
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
    public func remove(key: NSString) throws
    {
        let query = [kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String : service,
            kSecAttrAccount as String : key
        ]
        
        let status = SecItemDelete(query)
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
    public func hasValidationValue() -> Bool
    {
        let query = [kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : validationService,
            kSecReturnData as String : true
        ]

        let status = SecItemCopyMatching(query, nil)
        return status == errSecSuccess
    }
    
    private var accessControl:SecAccessControl?
    private var validationService : String
    {
        return service as String + "_validation";
    }
}

//MARK: -
//MARK: Private methods
//MARK: -
private extension VKKeychain
{
    private func setValidationValue() throws
    {
        let value:String = "validation"
        var query = [kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : validationService,
            kSecValueData as String : value.dataUsingEncoding(NSUTF8StringEncoding)!,
            kSecAttrAccessible as String : kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ]
        if #available(iOS 9.0, *)
        {
            query[kSecUseAuthenticationUI as String] = kCFBooleanFalse
        }
        else
        {
            query[kSecUseNoAuthenticationUI as String] = kCFBooleanTrue
        }
        let status = SecItemAdd(query, nil)
        if status != errSecSuccess
        {
            throw securityError(status: status)
        }
    }
    
    private func resetValidationValue() throws
    {
        let query = [kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : validationService]
        let status = SecItemDelete(query)
        if ((status != errSecSuccess) && (status != errSecItemNotFound))
        {
            throw securityError(status: status)
        }
    }
    
    private func query(key : NSString, value:NSData? = nil) throws -> [String: AnyObject]
    {
        var query:[String:AnyObject] = [kSecClass as String:kSecClassGenericPassword,
            kSecAttrLabel as String   : label,
            kSecAttrService as String : service,
            kSecAttrAccount as String : key
        ]
        
        #if !((arch(i386) || arch(x86_64)) && os(iOS))
            if let accessGroup = self.accessGroup
            {
                query[kSecAttrAccessGroup as String] = accessGroup
            }
        #endif
        
        if (touchIdEnabled)
        {
            var error: Unmanaged<CFError>?
            if (accessControl == nil)
            {
                accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .UserPresence, &error)
            }
            
            guard let accessControl = accessControl
                else
            {
                var errorToThrow : NSError? = error?.takeUnretainedValue() as NSError?
                if errorToThrow == nil
                {
                    errorToThrow = NSError(domain: "KeychainDomain", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create access control object"])
                }
                throw errorToThrow!
            }
            
            query[kSecAttrAccessControl as String] = accessControl
        }
        return query
    }
    
    private class func securityError(status status: OSStatus) -> NSError
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
    
    private func securityError(status status: OSStatus) -> NSError
    {
        return self.dynamicType.securityError(status: status)
    }
}
