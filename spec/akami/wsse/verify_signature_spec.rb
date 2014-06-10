require 'spec_helper'

describe Akami::WSSE::VerifySignature do

  it 'should validate correctly signed XML messages' do
    xml = fixture('akami/wsse/verify_signature/valid.xml')
    validator = described_class.new(xml)
    validator.verify!.should eq(true)
  end

  it 'should validate correctly signed XML messages with differently named namespaces' do
    xml = fixture('akami/wsse/verify_signature/valid_namespaces.xml')
    validator = described_class.new(xml)
    validator.verify!.should eq(true)
  end

  it 'should not validate signed XML messages with digested content changed' do
    xml = fixture('akami/wsse/verify_signature/invalid_digested_changed.xml')
    validator = described_class.new(xml)
    expect{ validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  it 'should not validate signed XML messages with digest changed' do
    xml = fixture('akami/wsse/verify_signature/invalid_digest_changed.xml')
    validator = described_class.new(xml)
    expect{ validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  it 'should not validate signed XML messages with signature changed' do
    xml = fixture('akami/wsse/verify_signature/invalid_signature_changed.xml')
    validator = described_class.new(xml)
    expect{ validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

end
