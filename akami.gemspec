# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "akami/version"

Gem::Specification.new do |s|
  s.name        = "akami"
  s.version     = Akami::VERSION
  s.authors     = ["Daniel Harrington"]
  s.email       = ["me@rubiii.com"]
  s.homepage    = "https://github.com/savonrb/#{s.name}"
  s.summary     = "Web Service Security"
  s.description = "Building Web Service Security"
  s.required_ruby_version = '>= 2.7.0'

  s.license = "MIT"

  s.add_dependency "gyoku", ">= 0.4.0"
  s.add_dependency "nokogiri"

  s.add_development_dependency "rake",    "~> 13.0"
  s.add_development_dependency "rspec",   "~> 3.12"
  s.add_development_dependency "timecop", "~> 0.5"
  s.add_development_dependency "debug"

  s.metadata = { "rubygems_mfa_required" => "true" }

  s.files = Dir["lib/**/*"] + %w[CHANGELOG.md LICENSE README.md]
  s.require_paths = ["lib"]
end
