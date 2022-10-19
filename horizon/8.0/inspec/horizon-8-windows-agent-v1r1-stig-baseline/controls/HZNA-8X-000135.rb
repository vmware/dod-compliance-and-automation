control 'HZNA-8X-000135' do
  title 'The Horizon Agent must audit clipboard actions.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to flow over channels that are provided for that explicit purpose and are monitored appropriately.

    By default, the Horizon Agent will block clipboard \"copy/paste\" actions from the VDI desktop to the client but will allow \"copy/paste\" actions from the client to the VDI desktop. All such allowed actions must be audited for potential future forensic purposes.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Clipboard Redirection.

    Double-click the \"Configure clipboard audit\" setting.

    If \"Configure clipboard audit\" is set to either \"Not Configured\" or \"Disabled\", this is a finding.

    In the drop-down under \"Configure clipboard audit\", if \"Enabled in both directions\" is not selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Clipboard Redirection.

    Double-click the \"Configure clipboard audit\" setting.

    Ensure \"Configure clipboard audit\" is set to \"Enabled\".

    In the drop-down under \"Configure clipboard audit\", select \"Enabled in both directions\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000135'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Clipboard Redirection') do
    it { should have_property 'ClipboardAuditState' }
    its('ClipboardAuditState') { should cmp 3 }
  end
end
