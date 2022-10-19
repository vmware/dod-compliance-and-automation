control 'HZNC-8X-000133' do
  title 'The Horizon Client must check certificate revocation status.'
  desc  "
    Preventing the disclosure of transmitted information requires that the device or machine take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

    The Horizon Client connects to the Connection Server, UAG or other gateway via a TLS connection. This initial connection must be trusted, otherwise the sensitive information flowing over the tunnel could potentially be open to interception. The Horizon Client can be configured to not check certificate revocation status. This must not be allowed and must be validated and maintained over time.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    If \"Do not check certificate revocation status\" is set to \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Do not check certificate revocation status\".

    Ensure \"Do not check certificate revocation status\" is set to either \"Not configured\" or \"Disabled\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000133'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  reg = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security')

  if reg.has_property?('IgnoreRevocation')
    describe reg do
      its('IgnoreRevocation') { should cmp 'false' }
    end
  else
    describe reg do
      it { should_not have_property 'IgnoreRevocation' }
    end
  end
end
