control 'HZNA-8X-000136' do
  title 'The Horizon Agent must enable screen blanking for Blast to disable access to a VDI Blast session from a vSphere console.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to be viewed by authorized individuals.

    By default, the Horizon Agent will display a blank screen for an active session when accessed through the VM console, but allows for mirroring the Blast screen to the VM console. This configuration option must be disabled, validated and maintained over time.

    Note: This control applies to VDI Blast sessions, and not RDSH sessions.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Blast.

    If \"Screen Blanking\" is not set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Blast.

    Double-click the \"Screen Blanking\" setting.

    Ensure \"Screen Blanking\" is set to \"Enabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-HZNA-8X-000136'
  tag rid: 'SV-HZNA-8X-000136'
  tag stig_id: 'HZNA-8X-000136'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware Blast\\Config') do
    it { should have_property 'BlankScreenEnabled' }
    its('BlankScreenEnabled') { should cmp 1 }
  end
end
