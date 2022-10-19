control 'HZNA-8X-000128' do
  title 'The Horizon Agent must check the entire chain when validating certificates.'
  desc  "
    Any time the Horizon Agent establishes an outgoing TLS connection, it verifies the server certificate revocation status. By default, it verifies all intermediate certificates, but does not verify the root.

    DoD policy requires full path validation, so this default behavior must be changed in order to comply.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Common Configuration >> Security Configuration.

    Double-click the \"Type of certificate revocation check\" setting.

    If \"Type of certificate revocation check\" is set to either \"Not Configured\" or \"Disabled\", this is a finding.

    In the drop-down under \"Type of certificate revocation check\", if \"WholeChain\" is not selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_agent*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon settings to the VDI desktops or RDS hosts.

    Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Common Configuration >> Security Configuration.

    Double-click the \"Type of certificate revocation check\" setting.

    Ensure \"Type of certificate revocation check\" is set to \"Enabled\".

    In the drop-down under \"Type of certificate revocation check\", select \"WholeChain\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNA-8X-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonagenthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Security') do
    it { should have_property 'CertificateRevocationCheckType' }
    its('CertificateRevocationCheckType') { should cmp 3 }
  end
end
