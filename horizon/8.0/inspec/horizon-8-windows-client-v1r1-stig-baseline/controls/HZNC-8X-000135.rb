control 'HZNC-8X-000135' do
  title 'The Horizon Client must use approved ciphers.'
  desc  "
    The Horizon Client disables the older TLS v1.0 protocol and the SSL v2 and SSL v3 protocols by default. TLS v1.1 is still enabled in the default configuration, despite known shortcomings, for the sake of backward compatibility with older servers and clients. The Horizon Connection Server STIG mandates TLS v1.2 in order to protect sensitive data-in-flight and the Client must follow suit.

    Note: Mandating TLS 1.2 may affect certain thin and zero clients. Test and implement carefully.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Configures SSL protocols and cryptographic algorithms\".

    If \"Configures SSL protocols and cryptographic algorithms\" is set to either \"Disabled\" or \"Not Configured\", this is a finding.

    If the field beneath \"Configures SSL protocols and cryptographic algorithms\" is not set to \"TLSv1.2:!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES\", this is a finding.
  "
  desc 'fix', "
    Ensure the vdm_client*.admx templates have been added to the Active Directory Domain.

    Open the \"Group Policy Management\" MMC snap-in, then open the applicable GPO that is applying the Horizon Client settings to the desktop machines.

    Navigate to Computer Configuration >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings.

    Double-click \"Configures SSL protocols and cryptographic algorithms\".

    Ensure \"Configures SSL protocols and cryptographic algorithms\" is set to \"Enabled\".

    In the field beneath \"Configures SSL protocols and cryptographic algorithms\", type the following:

    TLSv1.2:!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES

    Click \"OK\".

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNC-8X-000135'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonclienthelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\VMware, Inc.\\VMware VDM\\Client\\Security') do
    it { should have_property 'SSLCipherList' }
    its('SSLCipherList') { should cmp 'TLSv1.2:!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES' }
  end
end
