control 'HZNA-8X-000130' do
  title 'The Horizon Agent must block VDI desktop to client clipboard actions.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to flow over channels that are provided for that explicit purpose and are monitored appropriately.

    By default, the Horizon Agent will block clipboard \"copy/paste\" actions from the VDI desktop to the client but will allow those actions from the client to the VDI desktop. This configuration must be validated and maintained over time.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Clipboard Redirection.

    Double-click the \"Configure clipboard redirection\" setting.

    If \"Configure clipboard redirection\" is set to either \"Not Configured\" or \"Disabled\", this is not a finding.

    In the drop-down under \"Configure clipboard redirection\", if either \"Enabled server to client only\" or \"Enabled in both directions\" is selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Clipboard Redirection.

    Double-click the \"Configure clipboard redirection\" setting.

    Ensure \"Configure clipboard redirection\" is set to \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000130'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  reg = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Clipboard Redirection')

  describe.one do
    describe reg do
      it { should_not exist }
    end

    describe reg do
      it { should_not have_property 'ClipboardState' }
    end

    describe reg do
      its('ClipboardState') { should be_in ['0', '2'] }
    end
  end
end
