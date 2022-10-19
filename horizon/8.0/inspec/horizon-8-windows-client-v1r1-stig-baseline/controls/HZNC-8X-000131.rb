control 'HZNC-8X-000131' do
  title 'The Horizon Client must not connect to servers without fully verifying the server certificate.'
  desc  "
    Preventing the disclosure of transmitted information requires that the device or machine take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

    The Horizon Client connects to the Connection Server, UAG or other gateway via a TLS connection. This initial connection must be trusted, otherwise the sensitive information flowing over the tunnel could potentially be open to interception. The Horizon Client can be configured to ignore any certificate validation errors, warn, or fail.

    By default, the Client will warn and let the user decide whether to proceed or not. This decision must not be left to the end user. In a properly configured, enterprise environment, there should be no issues with the presented certificate. On the other hand, allowing the end user to click through any errors allows a TLS connection to be intercepted and subjected to a man-in-the-middle attack.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Certificate verification mode\".

    If \"Certificate verification mode\" is set to \"Not Configured\" or \"Disabled\", this is a finding.

    If the dropdown for \"Certificate verification mode\" is not set to \"Full Security\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Certificate verification mode\".

    Make sure \"Certificate verification mode\" is set to \"Enabled\".

    In the dropdown below \"Certificate verification mode\", select \"Full Security\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000131'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security') do
    it { should have_property 'CertCheckMode' }
    its('CertCheckMode') { should cmp '2' }
  end
end
