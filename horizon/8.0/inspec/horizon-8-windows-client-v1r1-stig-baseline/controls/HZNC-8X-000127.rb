control 'HZNC-8X-000127' do
  title 'The Horizon Client must not allow unauthenticated access.'
  desc  "
    When the Horizon native smart card capability is not set to \"Required\", the option for \"Unauthenticated Access\" is enabled. The \"Unauthenticated Access\" option allows users to access published applications from a Horizon Client without requiring AD credentials. This is typically implemented as a convenience when serving up an application that has its own security and user management. This configuration is not acceptable in the DoD and must be disabled.

    In certain configurations, connections can be made directly to a machine with the Horizon Agent installed, potentially bypassing the Connection Server having unauthenticated access disabled. Because of that, the Client must also be configured to not allow unauthenticated access.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    If \"Enable Unauthenticated Access to the server\" is not set to \"Disabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Scripting definitions.

    Ensure \"Enable Unauthenticated Access to the server\" is set to \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000127'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client') do
    it { should have_property 'UnauthenticatedAccessEnabled' }
    its('UnauthenticatedAccessEnabled') { should cmp 'false' }
  end
end
