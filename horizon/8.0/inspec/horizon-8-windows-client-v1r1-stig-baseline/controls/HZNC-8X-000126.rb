control 'HZNC-8X-000126' do
  title 'The Horizon Client must not store a logon password.'
  desc  'The Horizon Client allows for storing a username and password in order to facilitate authentication with a connection server. The password is stored in plain text in the registry. This configuration is not acceptable in the DoD and must not be enabled.'
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    If \"Logon Password\" is set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    Double-click the \"Logon Password\" setting.

    Ensure \"Logon Password\" is set to either \"Not Configured\" or \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000126'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client') do
    it { should_not have_property 'Password' }
  end
end
