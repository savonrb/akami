unless RUBY_PLATFORM.match?(/java/)
  require "simplecov"
  SimpleCov.start do
    add_filter "spec"
  end
end

require "bundler"
Bundler.require :default, :development

def fixture(local_path)
  File.read(File.join(File.dirname(__FILE__), "fixtures", local_path))
end
