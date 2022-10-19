control 'HZNA-8X-000124' do
  title 'The Horizon Agent must require TLS v1.2 connections.'
  desc  "
    The Horizon Agent has the capability to be backward compatible with legacy clients which do not support newer TLS connections. By default, the agent can fall back to this non-TLS mode when being accessed by a legacy client.

    The Horizon Agent must be configured to not support these legacy clients and enforce TLS connections as mandatory.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Security.

    If \"Accept SSL encrypted framework channel\" is not set to \"Enabled\", this is a finding.

    If the dropdown is not set to \"Enforce\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Security.

    Double-click the \"Accept SSL encrypted framework channel\" setting.

    Ensure \"Accept SSL encrypted framework channel\" is set to \"Enabled\" and the dropdown is set to \"Enforce\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000124'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Security') do
    it { should have_property 'AcceptTicketSSLAuth' }
    its('AcceptTicketSSLAuth') { should cmp 3 }
  end
end
