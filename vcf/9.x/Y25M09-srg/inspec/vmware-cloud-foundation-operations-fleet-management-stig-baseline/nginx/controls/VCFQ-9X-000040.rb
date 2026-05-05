control 'VCFQ-9X-000040' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server private keys must be protected from unauthorized access.'
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

    ssl_certificate_key /etc/nginx/ssl/cert.key;

    For each ssl_certificate_key returned, run the following command:

    # stat -c \"%n permisions are %a, is owned by %U and group owned by %G\" /etc/nginx/ssl/cert.key

    Example output:

    /etc/nginx/ssl/cert.key permisions are 600, is owned by nginx and group owned by nginx

    If any SSL key in use does not have permissions of 600 or less and owned by the user/group running the NGINX worker process or root, this is a finding.

    Note: Substitute the user and group name for the user defined to run the NGINX worker processes.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod 600 /etc/nginx/ssl/cert.key
    # chown nginx:nginx /etc/nginx/ssl/cert.key
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFQ-9X-000040'
  tag rid: 'SV-VCFQ-9X-000040'
  tag stig_id: 'VCFQ-9X-000040'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  nginx_user = input('nginx_user')
  nginx_group = input('nginx_group')

  keys = command('nginx -T 2>&1 | grep ssl_certificate_key').stdout

  if !keys.empty?
    keys.lines.each do |key|
      # extract key file path out of stdout
      key = key.scan(/key\s+(.*);/).flatten
      describe file(key[0]) do
        it { should_not be_more_permissive_than('0600') }
        its('owner') { should cmp('root').or cmp(nginx_user) }
        its('group') { should cmp('root').or cmp(nginx_group) }
      end
    end
  else
    describe 'No ssl keys found...' do
      skip 'No ssl keys found...skipping...'
    end
  end
end
