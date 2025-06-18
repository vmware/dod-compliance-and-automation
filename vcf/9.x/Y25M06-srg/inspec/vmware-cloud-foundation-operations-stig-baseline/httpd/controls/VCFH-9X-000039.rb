control 'VCFH-9X-000039' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service private keys must be protected from unauthorized access.'
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the server's private key is accessible only by admin with the following command:

    # find $(realpath /storage/vcops/user/conf/ssl/web_key.pem) -xdev -type f -a -exec stat -c %n:%a:%U:%G {} \\;

    Example result:

    /storage/vcops/user/conf/ssl/customKey.pem:400:admin:admin

    Note: The file name may vary but the permission and ownership must not.

    If the permission in the output is not set to 400, or the user or group are not set to admin, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s) for the <file> returned in the check with incorrect permission or ownership:

    # chmod 400 <file>
    # chown admin:admin <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFH-9X-000039'
  tag rid: 'SV-VCFH-9X-000039'
  tag stig_id: 'VCFH-9X-000039'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  sslkey = command('find $(realpath /storage/vcops/user/conf/ssl/web_key.pem) -type f -xdev').stdout.chomp

  if !sslkey.empty?
    describe file(sslkey) do
      it { should_not be_more_permissive_than('0400') }
      its('owner') { should cmp 'admin' }
      its('group') { should cmp 'admin' }
    end
  else
    describe 'The server private key' do
      subject { sslkey }
      it { should_not be_empty }
    end
  end
end
