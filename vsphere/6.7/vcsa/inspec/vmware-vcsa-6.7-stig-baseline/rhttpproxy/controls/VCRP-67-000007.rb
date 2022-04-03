control 'VCRP-67-000007' do
  title "The rhttpproxy private key file must be protected from unauthorized
access."
  desc  "The rhttpproxy's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the TLS traffic between a client and the web
server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c \"%n permissions are %a, is owned by %U and group owned by %G\"
/etc/vmware-rhttpproxy/ssl/rui.key

    Expected result:

    /etc/vmware-rhttpproxy/ssl/rui.key permissions are 600, is owned by root
and group owned by root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # chmod 600 /etc/vmware-rhttpproxy/ssl/rui.key
    # chown root:root /etc/vmware-rhttpproxy/ssl/rui.key
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-240722'
  tag rid: 'SV-240722r679679_rule'
  tag stig_id: 'VCRP-67-000007'
  tag fix_id: 'F-43914r679678_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file("#{input('sslKey')}") do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
  end
end
