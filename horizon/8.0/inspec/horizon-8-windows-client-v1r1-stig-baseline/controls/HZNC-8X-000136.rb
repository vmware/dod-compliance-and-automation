control 'HZNC-8X-000136' do
  title 'The Horizon Client must require TLS connections.'
  desc  "
    In older versions of Horizon, remote desktop connections could be established without TLS encryption. In order to protect data-in-transit when potentially connecting to very old Horizon servers, TLS tunnels must be mandated.

    The default configuration attempts TLS but will fall back to no encryption if TLS is not supported. This must be corrected and maintained over time.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Enable SSL encrypted framework channel\".

    If \"Enable SSL encrypted framework channel\" is set to either \"Disabled\" or \"Not Configured\", this is a finding.

    In the dropdown beneath \"Enable SSL encrypted framework channel\", if \"Enforce\" is not selected, this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Enable SSL encrypted framework channel\".

    Ensure \"Enable SSL encrypted framework channel\" is set to \"Enabled\".

    In the dropdown beneath \"Enable SSL encrypted framework channel\", select \"Enforce\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000136'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security') do
    it { should have_property 'EnableTicketSSLAuth' }
    its('EnableTicketSSLAuth') { should cmp '3' }
  end
end
