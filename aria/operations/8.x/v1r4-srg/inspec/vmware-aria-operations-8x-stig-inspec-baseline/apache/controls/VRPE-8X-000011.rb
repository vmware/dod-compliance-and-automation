control 'VRPE-8X-000011' do
  title "The VMware Aria Operations Apache server must only allow authenticated system administrators or the designated PKI Sponsor to access the web server's private key."
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the server's private key is accessible only by admin with the following command:

    # find /storage/vcops/user/conf/ssl/*key.pem -xdev -type f -a -exec stat -c %n:%a:%U:%G {} \\;

    Expected result:

    /storage/vcops/user/conf/ssl/cakey.pem:400:admin:admin
    /storage/vcops/user/conf/ssl/cluster_key.pem:400:admin:admin
    /storage/vcops/user/conf/ssl/postgres_vcops_key.pem:400:admin:admin
    /storage/vcops/user/conf/ssl/postgres_vcopsrepl_key.pem:400:postgres:root
    /storage/vcops/user/conf/ssl/slice_1_key.pem:400:admin:admin

    Note: The file name and numbers may vary but their permissions must not.

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s) for each <file> returned in the check with incorrect permissions:

    # chmod 400 <file>
    # chown admin:admin <file>

    Note: The postgres key may contain a different owner than \"admin\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-VRPE-8X-000011'
  tag rid: 'SV-VRPE-8X-000011'
  tag stig_id: 'VRPE-8X-000011'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']

  command('find /storage/vcops/user/conf/ssl/*key.pem -type f -xdev').stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0400') }
      its('owner') { should be_in ['admin', 'postgres'] }
    end
  end
end
