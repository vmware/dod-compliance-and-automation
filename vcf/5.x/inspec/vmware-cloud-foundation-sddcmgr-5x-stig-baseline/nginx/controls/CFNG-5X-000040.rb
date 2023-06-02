control 'CFNG-5X-000040' do
  title 'The SDDC Manager NGINX service must only allow authenticated system administrators access to certificate key files.'
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | grep 'ssl_certificate_key'

    Example result:

    ssl_certificate_key /etc/ssl/private/vcf_https.key;

    For each key returned, run the following command:

    # stat -c \"%n is owned by %U and group %G permissions are %a\" <path to key file>;

    If any key file is not owned by root or group root or permissions are more permissive than 640, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # chown root:root <key file>
    # chmod 640 <key file>

    Replace <key file> with the key files found with incorrect permissions or ownership.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-CFNG-5X-000040'
  tag rid: 'SV-CFNG-5X-000040'
  tag stig_id: 'CFNG-5X-000040'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  ssl_keys = command('nginx -T 2>&1 | grep "ssl_certificate_key" | cut -f 1 -d ";"').stdout.split.keep_if { |fname| fname != 'ssl_certificate_key' }
  ssl_keys.each do |key|
    describe file(key) do
      its('group') { should cmp 'root' }
      its('owner') { should cmp 'root' }
      it { should_not be_more_permissive_than('0640') }
    end
  end
end
