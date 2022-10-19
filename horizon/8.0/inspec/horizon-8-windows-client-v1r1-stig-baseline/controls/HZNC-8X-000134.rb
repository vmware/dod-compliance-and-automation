control 'HZNC-8X-000134' do
  title 'The Horizon Client must not display the option to log in as the current user.'
  desc  "
    Horizon Connection Server has the ability to allow clients to authenticate using the local session credentials of their local endpoint. While convenient, this must be disabled for DoD deployments as the server cannot ascertain the method of endpoint login, whether that user's client certificate has since been revoked, and other reasons.

    This option is disabled in the Horizon Connection Server STIG, and must also be disabled on the client to avoid confusion.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration. >> Security Settings.

    If \"Display option to Log in as current user\" is not set to \"Disabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Display option to Log in as current user\".

    Ensure \"Display option to Log in as current user\" is set to \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000134'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security') do
    it { should have_property 'LogInAsCurrentUser_Display' }
    its('LogInAsCurrentUser_Display') { should cmp 'false' }
  end
end
