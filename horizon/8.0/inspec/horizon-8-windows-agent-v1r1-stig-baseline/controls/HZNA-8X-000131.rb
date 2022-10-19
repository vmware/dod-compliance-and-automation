control 'HZNA-8X-000131' do
  title 'The Horizon Agent must not allow unauthenticated access.'
  desc  "
    When the Horizon native smart card capability is not set to \"Required\", the option for \"Unauthenticated Access\" is enabled. The \"Unauthenticated Access\" option allows users to access published applications from a Horizon Client without requiring AD credentials. This is typically implemented as a convenience when serving up an application that has its own security and user management. This configuration is not acceptable in the DoD and must be disabled.

    In certain configurations, connections can be made directly to a machine with the Horizon Agent installed, potentially bypassing the Connection Server having unauthenticated access disabled. Because of that, the Agent must also be configured to not allow unauthenticated access.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    If \"Enable Unauthenticated Access\" is set to either \"Not Configured\" or \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration.

    Double-click the \"Enable Unauthenticated Access\" setting.

    Ensure \"Enable Unauthenticated Access\" is set to \"Disabled\".

    Click \"OK\".

    Note: The machine must be rebooted for the setting to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000131'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Agent\\Configuration') do
    it { should have_property 'UnAuthenticatedAccessEnabled' }
    its('UnAuthenticatedAccessEnabled') { should cmp 0 }
  end
end
