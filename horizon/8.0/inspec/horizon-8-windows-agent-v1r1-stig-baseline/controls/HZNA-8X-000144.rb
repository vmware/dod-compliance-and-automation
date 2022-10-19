control 'HZNA-8X-000144' do
  title 'The Horizon Agent must set an RDS idle timeout value.'
  desc  "
    Idle sessions present an increased risk of being hijacked. If a user steps away from their desk and is no longer in positive control of their session, that session is in danger of being assumed by another user. Idle sessions can also waste valuable datacenter resources, which in turn may lead to a lack of resources for new, active users.

    Because of these and other reasons, an organizationally defined idle timeout value must be configured to override the RDS idle timeout default value of \"never\".
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"RDS Idle Time Until Disconnect\" setting.

    If \"RDS Idle Time Until Disconnect\" is set to either \"Not Configured\" or \"Disabled\", this is a finding.

    In the drop-down next to \"RDS Idle Timeout\", if \"Never\" is selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"RDS Idle Time Until Disconnect\" setting.

    Ensure \"RDS Idle Time Until Disconnect\" is set to \"Enabled\".

    In the drop-down next to \"RDS Idle Timeout\", select an appropriate, site-specific timeout value that is not \"Never\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000144'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Configuration') do
    it { should have_property 'RDSIdleTimeout' }
    its('RDSIdleTimeout') { should_not cmp 0 }
  end
end
