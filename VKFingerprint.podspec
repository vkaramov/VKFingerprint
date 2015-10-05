#
# Be sure to run `pod lib lint VKFingerprint.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = "VKFingerprint"
  s.version          = "1.0.0"
  s.summary          = "Simple Fingerprint Swift wrapper for iOS"

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!  
  s.description      = <<-DESC
Lightweight fingerprint library written in Swift. Enables fingerprint scanner usage for the capable iOS devices
                       DESC

  s.homepage         = "https://github.com/vkaramov/VKFingerprint"
  s.license          = 'MIT'
  s.author           = { "Viacheslav Karamov" => "vkaramov a_t yandex dot ru" }
  s.source           = { :git => "https://github.com/vkaramov/VKFingerprint.git", :tag => s.version.to_s }

  s.platform     = :ios, '8.0'
  s.requires_arc = true

  s.source_files = 'Pod/Classes/**/*'
  s.resource_bundles = {
    'VKFingerprint' => ['Pod/Assets/*.png']
  }

  s.frameworks = 'Foundation', 'Security', 'LocalAuthentication'
end
