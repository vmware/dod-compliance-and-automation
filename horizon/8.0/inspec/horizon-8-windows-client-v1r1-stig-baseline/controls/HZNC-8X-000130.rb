control 'HZNC-8X-000130' do
  title 'The Horizon Client must not allow command line credentials.'
  desc  'The Horizon Client by default has a number of command line options, including authentication parameters. These can include a smart card PIN, if configured by the end user. This would normally be implemented by a script, which would then mean plain text sensitive authenticators would be stored on disk. Hard coding of credentials of any variety, especially smart card PINs, must be explicitly disallowed.'
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    If \"Allow command line credentials\" is set to \"Not Configured\" or \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Allow command line credentials\".

    Ensure \"Allow command line credentials\" is set to \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000130'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security') do
    it { should have_property 'AllowCmdLineCredentials' }
    its('AllowCmdLineCredentials') { should cmp 'false' }
  end
end
