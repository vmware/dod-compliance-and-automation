control 'VCFJ-9X-000039' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service private keys must be protected from unauthorized access.'
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # stat -c \"%n permisions are %a, is owned by %U and group owned by %G\" /common/httpd/.privatekey.pem

    Example output:

    /common/httpd/.privatekey.pem permisions are 600, is owned by admin and group owned by secureall

    If the SSL key does not have permissions of 600 or more restrictive and owned by the user/group running the httpd worker process or root, this is a finding.

    Note: Substitute the user and group name for the user defined to run the httpd worker processes.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod 600 /common/httpd/.privatekey.pem
    # chown admin:secureall /common/httpd/.privatekey.pem
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFJ-9X-000039'
  tag rid: 'SV-VCFJ-9X-000039'
  tag stig_id: 'VCFJ-9X-000039'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  apache_httpd_user = input('apache_httpd_user')
  apache_httpd_group = input('apache_httpd_group')
  apache_private_key = input('apache_private_key')

  describe file(apache_private_key) do
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should cmp('root').or cmp(apache_httpd_user) }
    its('group') { should cmp('root').or cmp(apache_httpd_group) }
  end
end
