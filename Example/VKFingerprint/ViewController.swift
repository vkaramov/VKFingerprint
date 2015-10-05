//
//  ViewController.swift
//  VKFingerprint
//
//  Created by Viacheslav Karamov on 01.10.15.
//  Copyright © 2015 Viacheslav Karamov. All rights reserved.
//

import UIKit
import VKFingerprint

class ViewController: UIViewController {

    @IBOutlet weak var keyField: UITextField!
    @IBOutlet weak var valueField: UITextField!
    
    private var fingerprint = VKFingerprint(label: "Some interesting value...", touchIdEnabled: true, accessGroup: nil, service: nil)
    
    override func viewDidLoad()
    {
        super.viewDidLoad()
    }

    @IBAction func writeValueTapped(sender: UIButton)
    {
        fingerprint.setStringValue(valueField.text!, forKey: keyField.text!) { (completed: Bool) -> Void in
            let text = completed ? "Value written!" : "Error writing value";
            self.showAlert(text);
        }
    }

    @IBAction func readValueTapped(sender: UIButton)
    {
        fingerprint.getString(forKey: keyField.text!) { (error, value) -> Void in
            if let error = error
            {
                self.showAlert("Failed to read value for key \(self.keyField.text!), error: \(error)");
            }
            else
            {
                self.showAlert("Read value is: \(value)");
            }
        }
    }
    
    @IBAction func clearTapped(sender: UIButton)
    {
        fingerprint.resetValue(forKey: keyField.text!, completion: { (completed) -> Void in
            let text = completed ? "Value cleared!" : "Failed to crear value";
            self.showAlert(text);
        })
    }
    
    @IBAction func validateTapped(sender: UIButton)
    {
        fingerprint.validateValue() {
            let text = $0 ? "Validation value is present" : "Validation value is missing";
            self.showAlert(text);
        }
    }
    
    private func showAlert(text : String)
    {
        let alertController = UIAlertController(title: nil, message: text, preferredStyle: .Alert)
        let OKAction = UIAlertAction(title: "OK", style: .Default) { (action) in
            self.keyField.resignFirstResponder();
            self.valueField.resignFirstResponder();
        }
        alertController.addAction(OKAction)

        presentViewController(alertController, animated:true)
        {
        }
    }
}

