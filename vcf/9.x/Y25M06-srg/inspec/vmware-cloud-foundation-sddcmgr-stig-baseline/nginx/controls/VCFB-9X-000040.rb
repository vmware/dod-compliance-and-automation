control 'VCFB-9X-000040' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server private keys must be protected from unauthorized access.'
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify file permissions on private keys.

    View the defined SSL certificate keys by running the following command:

    # nginx -T 2>&1 | grep ssl_certificate_key

    Example output:

    ssl_certificate_key /etc/ssl/private/vcf_https.key;

    For each ssl_certificate_key returned, run the following command:

    # stat -c \"%n permisions are %a, is owned by %U and group owned by %G\" /etc/ssl/private/vcf_https.key

    Example output:

    /etc/ssl/private/vcf_https.key permisions are 640, is owned by root and group owned by root

    If any key file is not owned by root or group root or permissions are more permissive than 640, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following:

    # chown root:root <key file>
    # chmod 640 <key file>

    Replace <key file> with the key files found with incorrect permissions or ownership.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFB-9X-000040'
  tag rid: 'SV-VCFB-9X-000040'
  tag stig_id: 'VCFB-9X-000040'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  keys = command('nginx -T 2>&1 | grep ssl_certificate_key').stdout

  if !keys.empty?
    keys.lines.each do |key|
      # extract key file path out of stdout
      key = key.scan(/key\s(.*);/).flatten
      describe file(key[0]) do
        it { should_not be_more_permissive_than('0640') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'No ssl keys found...' do
      skip 'No ssl keys found...skipping...'
    end
  end
end
