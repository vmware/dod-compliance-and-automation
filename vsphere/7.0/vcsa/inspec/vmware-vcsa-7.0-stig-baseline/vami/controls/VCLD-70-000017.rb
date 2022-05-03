control 'VCLD-70-000017' do
  title 'VAMI must protect the keystore from unauthorized access.'
  desc  "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients. By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c \"%n has %a permissions and is owned by %U:%G\" /etc/applmgmt/appliance/server.pem

    Expected result:

    /etc/applmgmt/appliance/server.pem has 600 permissions and is owned by root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # chown root:root /etc/applmgmt/appliance/server.pem
    # chmod 600 /etc/applmgmt/appliance/server.pem
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000017'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file("#{input('serverCert')}") do
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end
