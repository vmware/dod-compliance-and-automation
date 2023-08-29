control 'WOAT-3X-000043' do
  title 'Workspace ONE Access must only allow authenticated system administrators to have access to the keystore.'
  desc  "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.TC Server stores the server's private key in a keystore file.  The vCSA keystore file is tcserver.keystore, and this file must be protected to only allow system administrator's and other authorized users to have access to it."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n is owned by %U and group %G permissions are %a\" /opt/vmware/horizon/workspace/conf/tcserver.keystore

    If key file is not owned by horizon or group www or permissions are more permissive than 640, this is a finding.

  "
  desc 'fix', "
    At the command line, execute the following command:

    #  chown horizon:www <key file>
    # chmod 640 <key file>

    Replace <key file> with the key files found with incorrect permissions or ownership.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-WOAT-3X-000043'
  tag rid: 'SV-WOAT-3X-000043'
  tag stig_id: 'WOAT-3X-000043'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file('/opt/vmware/horizon/workspace/conf/tcserver.keystore') do
    its('owner') { should cmp 'horizon' }
    its('group') { should cmp 'www' }
    it { should_not be_more_permissive_than('0640') }
  end
end
