# frozen_string_literal: true

source 'https://rubygems.org'
gemspec

group :test, :development do
  gem 'bundler-audit', '~> 0.9.3', require: false
  # ruby_audit 3.x requires Ruby >= 3.1. Only the CI audit job needs it.
  gem 'ruby_audit', '~> 3.1', require: false if RUBY_VERSION >= '3.1.0'
  gem 'simplecov', require: false
  gem 'standard', '>= 1.35.1', require: false

  gem 'license_finder', require: false
  gem 'rubocop'
  gem 'rubocop-performance'
  gem 'rubocop-rspec'
end
