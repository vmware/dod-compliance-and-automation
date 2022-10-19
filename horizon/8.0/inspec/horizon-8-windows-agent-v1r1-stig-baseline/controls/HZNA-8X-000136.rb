control 'HZNA-8X-000136' do
  title 'The Horizon Agent must enable screen blanking for Blast.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to be viewed by authorized individuals.

    By default, the Horizon Agent will display a blank screen for an active session when accessed through the VM console, but allows for mirroring the Blast screen to the VM console. This configuration option must be disabled, validated and maintained over time.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Blast.

    If \"Screen Blanking\" is set to either \"Not Configured\" or \"Enabled\", this is not a finding.

    If \"Screen Blanking\" is set to \"Disabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Blast.

    Double-click the \"Screen Blanking\" setting.

    Ensure \"Screen Blanking\" is set to either \"Enabled\" or \"Not Configured\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000136'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware Blast\\Config') do
      it { should_not have_property 'BlankScreenEnabled' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware Blast\\Config') do
      it { should have_property 'BlankScreenEnabled' }
      its('BlankScreenEnabled') { should_not cmp 0 }
    end
  end
end
