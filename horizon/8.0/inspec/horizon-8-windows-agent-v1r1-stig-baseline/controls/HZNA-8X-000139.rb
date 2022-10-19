control 'HZNA-8X-000139' do
  title 'The Horizon Agent must be installed in FIPS mode.'
  desc  "
    Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms or poor implementation.

    The Horizon Connection Server and Agent can both be configured to exclusively use FIPS 140-2 validated cryptographic modules but only at installation time, not post deployment. Reference VMware documentation for up-to-date requirements for enabling FIPS during the Horizon Agent install.
  "
  desc  'rationale', ''
  desc  'check', "
    On the template Virtual Machine, or on a resultant cloned machine, where the Horizon Agent is installed, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\" and locate the \"FipsMode\" key.

    If \"FipsMode\" does not exist, or does not have a value of \"1\", this is a finding.
  "
  desc 'fix', "
    FIPS mode can only be implemented during installation. Reinstall the Horizon Agent on the template Virtual Machine and select the option to enable FIPS mode.

    Note: The Horizon Agent can only be installed in FIPS mode if the Windows machine itself is running in FIPS mode.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000139'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware VDM') do
    it { should have_property 'FipsMode' }
    its('FipsMode') { should cmp 1 }
  end
end
