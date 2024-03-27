control 'VLMN-8X-000040' do
  title 'The VMware Aria Suite Lifecycle web service private keys must be protected from unauthorized access.'
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

    ssl_certificate_key /opt/vmware/vlcm/server.key;

    For each ssl_certificate_key returned, run the following command:

    # stat -c \"%n permisions are %a, is owned by %U and group owned by %G\" /opt/vmware/vlcm/server.key

    Example output:

    /opt/vmware/vlcm/server.key permisions are 400, is owned by root and group owned by root

    If any SSL key in use does not have permissions of 400 and owned by the user/group running the NGINX worker process, this is a finding.

    Note: Substitute the user and group name for the user defined to run the NGINX worker processes.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 400 /opt/vmware/vlcm/server.key
    # chown root:root /opt/vmware/vlcm/server.key

    Note: Substitute the path for the user defined to run the worker processes.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-VLMN-8X-000040'
  tag rid: 'SV-VLMN-8X-000040'
  tag stig_id: 'VLMN-8X-000040'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  nginx_user = input('nginx_user')
  nginx_group = input('nginx_group')

  keys = command('nginx -T 2>&1 | grep ssl_certificate_key').stdout

  if !keys.empty?
    keys.lines.each do |key|
      # extract key file path out of stdout
      keyfile = key.scan(/key\s(.*);/).flatten[0].strip
      describe file(keyfile) do
        it { should_not be_more_permissive_than('0400') }
        its('owner') { should cmp nginx_user }
        its('group') { should cmp nginx_group }
      end
    end
  else
    describe 'No ssl keys found...' do
      skip 'No ssl keys found...skipping...'
    end
  end
end
