control 'VCRP-80-000040' do
  title 'The vCenter Envoy service private key file must be protected from unauthorized access.'
  desc  "
    Envoy's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the Transport Layer Security (TLS) traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c \"%n permissions are %a, is owned by %U and group owned by %G\" /etc/vmware-rhttpproxy/ssl/rui.key

    Expected result:

    /etc/vmware-rhttpproxy/ssl/rui.key permissions are 600, is owned by rhttpproxy and group owned by rhttpproxy

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod 600 /etc/vmware-rhttpproxy/ssl/rui.key
    # chown rhttpproxy:rhttpproxy /etc/vmware-rhttpproxy/ssl/rui.key
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-VCRP-80-000040'
  tag rid: 'SV-VCRP-80-000040'
  tag stig_id: 'VCRP-80-000040'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file('/etc/vmware-rhttpproxy/ssl/rui.key') do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'rhttpproxy' }
    its('group') { should cmp 'rhttpproxy' }
  end
end
