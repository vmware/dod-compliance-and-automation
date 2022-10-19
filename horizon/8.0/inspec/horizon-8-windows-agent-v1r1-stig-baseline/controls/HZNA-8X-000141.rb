control 'HZNA-8X-000141' do
  title 'The Horizon Agent must set an RDS connection to disconnect after a maximum of 10 hours.'
  desc  'Horizon VDI is intended to provide remote desktops and applications, generally during working hours, and for no more than an extended workday. Leaving sessions active for more than what is reasonable for a work day opens the possibility of a session becoming unoccupied and insecure on the client side. For example, if a client connection is opened at 0900, there are few day-to-day reasons that the connection should still be open after 1900, therefore the connection must be terminated. If the user is still active, and environment settings allow it, they can re-authenticate immediately and continue the session.'
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"RDS Connection Time Until Disconnect\" setting.

    If \"RDS Connection Time Until Disconnect\" is set to either \"Not Configured\" or \"Disabled\", this is a finding.

    In the drop-down next to \"RDS Connection Timeout\", if \"Never\" is selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"RDS Connection Time Until Disconnect\" setting.

    Ensure \"RDS Connection Time Until Disconnect\" is set to \"Enabled\".

    In the drop-down next to \"RDS Connection Timeout\", select an appropriate, site-specific timeout value that is not \"Never\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000141'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Configuration') do
    it { should have_property 'RDSConnectTimeout' }
    its('RDSConnectTimeout') { should_not cmp 0 }
  end
end
