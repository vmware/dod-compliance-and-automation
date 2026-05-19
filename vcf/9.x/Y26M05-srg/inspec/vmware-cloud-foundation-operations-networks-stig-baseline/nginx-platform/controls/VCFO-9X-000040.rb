control 'VCFO-9X-000040' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server private keys must be protected from unauthorized access.'
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify file permissions on private keys.

    View the defined SSL certificate keys by running the following command:

    # nginx -T 2>&1 | grep ssl_certificate_key | grep -v \"#\"

    Example output:

    ssl_certificate_key /etc/nginx/ssl/vnera.com.key;

    For each ssl_certificate_key returned, run the following command:

    # stat -c \"%n permisions are %a, is owned by %U and group owned by %G\" /etc/nginx/ssl/vnera.com.key

    Example output:

    /etc/nginx/ssl/vnera.com.key permisions are 640, is owned by root and group owned by root

    If any SSL key in use does not have permissions of 640 or more restrictive and owned by root and group owned by root, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod 640 /etc/nginx/ssl/vnera.com.key
    # chown root:root /etc/nginx/ssl/vnera.com.key
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFO-9X-000040'
  tag rid: 'SV-VCFO-9X-000040'
  tag stig_id: 'VCFO-9X-000040'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  keys = command('nginx -T 2>&1 | grep ssl_certificate_key | grep -v "#"').stdout

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
