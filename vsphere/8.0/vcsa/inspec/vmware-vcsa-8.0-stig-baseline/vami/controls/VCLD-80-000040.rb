control 'VCLD-80-000040' do
  title 'The vCenter VAMI service must restrict access to the web servers private key.'
  desc  "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients. By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the Secure Sockets Layer (SSL) traffic between a client and the web server."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c \"%n has %a permissions and is owned by %U:%G\" /etc/applmgmt/appliance/server.pem

    Expected result:

    /etc/applmgmt/appliance/server.pem has 600 permissions and is owned by root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chown root:root /etc/applmgmt/appliance/server.pem
    # chmod 600 /etc/applmgmt/appliance/server.pem
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-VCLD-80-000040'
  tag rid: 'SV-VCLD-80-000040'
  tag stig_id: 'VCLD-80-000040'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file('/etc/applmgmt/appliance/server.pem') do
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end
