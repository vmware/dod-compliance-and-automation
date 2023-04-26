control 'HZNC-8X-000138' do
  title 'The Horizon Client must be installed in FIPS mode.'
  desc  "
    Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms or poor implementation.

    The Horizon Connection Server, Agent and Client can all be configured to exclusively use FIPS 140-2 validated cryptographic modules but only at installation time, not post deployment. Reference VMware documentation for up-to-date requirements for enabling FIPS during the Horizon Client install.
  "
  desc  'rationale', ''
  desc  'check', "
    On the machine where the Horizon Client is installed, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\\Client\\Security\" and locate the \"EnableFIPSMode\" key.

    If \"EnableFIPSMode\" does not exist, or does not have a value of \"1\", this is a finding.
  "
  desc 'fix', "
    FIPS mode can only be implemented during installation. Reinstall the Horizon Client on the machine and select the option to enable FIPS mode.

    Note: The Horizon Client can only be installed in FIPS mode if the Windows machine itself is running in FIPS mode.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-HZNC-8X-000138'
  tag rid: 'SV-HZNC-8X-000138'
  tag stig_id: 'HZNC-8X-000138'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security') do
    it { should have_property 'EnableFIPSMode' }
    its('EnableFIPSMode') { should cmp '1' }
  end
end
