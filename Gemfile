source "https://rubygems.org"
gemspec

gem "bundler-audit", "~> 0.9.3", require: false
# ruby_audit 3.x requires Ruby >= 3.1. Only the CI audit job needs it.
gem "ruby_audit", "~> 3.1", require: false if RUBY_VERSION >= "3.1.0"
gem "simplecov", "< 1.1.0", require: false # simplecov 1.1.0 writes .resultset.json "timestamp" as a float, which the Coveralls reporter rejects (it parses the field as Int64). Unpin once coverallsapp/coverage-reporter accepts floats.
gem "standard", require: false
