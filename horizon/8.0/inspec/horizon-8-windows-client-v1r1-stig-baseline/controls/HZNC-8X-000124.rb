control 'HZNC-8X-000124' do
  title 'The Horizon Client must not send anonymized usage data.'
  desc  'By default, the Horizon Client collects anonymized data from the client systems to help improve software and hardware compatibility. To eliminate any possibility of sensitive DoD configurations being known to unauthorized parties, even when anonymized, this setting must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration.

    If \"Allow data sharing\" is set to \"Enabled\" or \"Not Configured\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration.

    Double-click the \"Allow data sharing\" setting.

    Ensure \"Allow data sharing\" is set to \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000124'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client') do
    it { should have_property 'AllowDataSharing' }
    its('AllowDataSharing') { should cmp 'false' }
  end
end
