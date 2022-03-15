control 'VCRP-67-000008' do
  title "The rhttproxy must exclusively use the HTTPS protocol for client
connections."
  desc  "Remotely accessing vCenter via the rhttpproxy involves sensitive
information going over the wire. To protect the confidentiality and integrity
of these communications, the rhttpproxy must be configured to use an encrypted
session of HTTPS rather than plain-text HTTP. The SSL configuration block
inside the rhttproxy configuration must be present and configured correctly to
safely enable TLS."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/config/ssl' /etc/vmware-rhttpproxy/config.xml

    Expected result:

    <ssl>
        <!-- The server private key file -->
        <privateKey>/etc/vmware-rhttpproxy/ssl/rui.key</privateKey>
        <!-- The server side certificate file -->
        <certificate>/etc/vmware-rhttpproxy/ssl/rui.crt</certificate>
        <!-- vecs server name. Currently vecs runs on all node types. -->
        <vecsServerName>localhost</vecsServerName>
      </ssl>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /etc/vmware-rhttpproxy/config.xml.

    Locate the first <ssl> block and set its content to the following:

    <ssl>
        <!-- The server private key file -->
        <privateKey>/etc/vmware-rhttpproxy/ssl/rui.key</privateKey>
        <!-- The server side certificate file -->
        <certificate>/etc/vmware-rhttpproxy/ssl/rui.crt</certificate>
        <!-- vecs server name. Currently vecs runs on all node types. -->
        <vecsServerName>localhost</vecsServerName>
    </ssl>

    Restart the service for changes to take effect.

    # vmon-cli --restart rhttpproxy
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag gid: 'V-240723'
  tag rid: 'SV-240723r679682_rule'
  tag stig_id: 'VCRP-67-000008'
  tag fix_id: 'F-43915r679681_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  describe xml("#{input('configXmlPath')}") do
    its(['/config/ssl/privateKey']) { should cmp "#{input('sslKey')}" }
    its(['/config/ssl/certificate']) { should cmp "#{input('certificateFile')}" }
    its(['/config/ssl/vecsServerName']) { should cmp "#{input('vecsServerName')}" }
  end
end
