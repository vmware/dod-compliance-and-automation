control 'HZNA-8X-000133' do
  title 'The Horizon Agent must not allow drag and drop.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to flow over channels that are provided for that explicit purpose and are monitored appropriately.

    By default, the Horizon Agent will allow drag and drop actions from the client to the VDI desktop. This must be configured to be disabled in both directions.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Drag and Drop.

    Double-click the \"Configure drag and drop direction\" setting.

    If \"Configure drag and drop direction\" is not set to \"Enabled\", this is a finding.

    In the drop-down under \"Configure drag and drop\", if \"Disabled in both directions\" is not selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Drag and Drop.

    Double-click the \"Configure drag and drop direction\" setting.

    Ensure \"Configure drag and drop direction\" is set to \"Enabled\".

    In the drop-down under \"Configure drag and drop\", select \"Disabled in both directions\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000133'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Drag and Drop') do
    it { should have_property 'DnDState' }
    its('DnDState') { should cmp 0 }
  end
end
