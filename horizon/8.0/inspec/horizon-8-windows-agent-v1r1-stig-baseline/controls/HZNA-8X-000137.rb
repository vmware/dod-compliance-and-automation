control 'HZNA-8X-000137' do
  title 'The Horizon Agent must not allow client drive redirection.'
  desc  "
    Data loss prevention is a primary concern for the DoD. Positive control of data must be maintained at all times, and data must only be allowed to flow over channels that are provided for that explicit purpose and are monitored appropriately.

    By default, the Horizon Client, Agent, and guest operating systems will coordinate to allow drives local to the client to be redirected over the Client connection and mounted in the virtual desktop. This configuration must be modified to disallow drive sharing in order to protect sensitive DoD data from being maliciously, accidentally, or casually removed from the controlled environment.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection.

    Double-click the \"Do not allow drive redirection\" setting.

    If \"Do not allow drive redirection\" is not set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection.

    Double-click the \"Do not allow drive redirection\" setting.

    Ensure \"Do not allow drive redirection\" is set to \"Enabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000137'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should cmp 1 }
  end
end
