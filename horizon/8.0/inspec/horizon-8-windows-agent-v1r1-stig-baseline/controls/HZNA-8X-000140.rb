control 'HZNA-8X-000140' do
  title 'The Horizon Agent must set a disconnected session time limit.'
  desc  "
    Disconnected sessions present an increased risk of being hijacked. If a user steps away from their desk, that disconnected session is in danger of being re-instantiated by another user. Disconnected sessions can also waste valuable datacenter resources, which in turn may lead to a lack of resources for new, active users.

    Because of these and other reasons, an organizationally defined disconnected session timeout value must be configured to override the Horizon default value of \"never\".
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"Disconnected Session Time Limit (VDI)\" setting.

    If \"Disconnected Session Time Limit (VDI)\" is set to either \"Not Configured\" or \"Disabled\", this is a finding.

    In the drop-down next to \"Disconnect Timeout\", if \"Never\" is selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"Disconnected Session Time Limit (VDI)\" setting.

    Ensure \"Disconnected Session Time Limit (VDI)\" is set to \"Enabled\".

    In the drop-down next to \"Disconnect Timeout\", select an appropriate, site-specific timeout value that is not \"Never\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000140'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Configuration') do
    it { should have_property 'VDIDisconnectTimeout' }
    its('VDIDisconnectTimeout') { should_not cmp 0 }
  end
end
