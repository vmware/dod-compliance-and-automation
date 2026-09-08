control 'VCFM-9X-000039' do
  title "The VMware Cloud Foundation vCenter VAMI Lighttpd service must restrict access to the web server's private key."
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # stat -c \"%n has %a permissions and is owned by %U:%G\" /etc/applmgmt/appliance/server.pem

    Example result:

    /etc/applmgmt/appliance/server.pem has 600 permissions and is owned by root:root

    If the server's private key is not owned by root with permissions of \"600\" or more restrictive, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chown root:root /etc/applmgmt/appliance/server.pem
    # chmod 600 /etc/applmgmt/appliance/server.pem
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFM-9X-000039'
  tag rid: 'SV-VCFM-9X-000039'
  tag stig_id: 'VCFM-9X-000039'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  describe file('/etc/applmgmt/appliance/server.pem') do
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end
