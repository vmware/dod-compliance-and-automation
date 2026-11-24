control 'VCFK-9X-000039' do
  title 'The VMware Cloud Foundation vCenter Envoy service private key file must be protected from unauthorized access.'
  desc  "
    The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At a command prompt, validate the vCenter Envoy service's private key is secure by running the following:

    # stat -c \"%n permissions are %a, is owned by %U and group owned by %G\" /etc/vmware-rhttpproxy/ssl/rui.key

    Example result:

    /etc/vmware-rhttpproxy/ssl/rui.key permissions are 600, is owned by rhttpproxy and group owned by rhttpproxy

    If the key file does not have permissions of \"600\" or more restrictive, this is a finding.
    If the key file owner is not \"rhttpproxy\", this is a finding.
    If the key file group is not \"rhttpproxy\", this is a finding.
  "
  desc 'fix', "
    At the command prompt, correct permissions for the Envoy private key by running the following:

    # chmod 600 /etc/vmware-rhttpproxy/ssl/rui.key
    # chown rhttpproxy:rhttpproxy /etc/vmware-rhttpproxy/ssl/rui.key
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag satisfies: ['SRG-APP-000915-WSR-000310']
  tag gid: 'V-VCFK-9X-000039'
  tag rid: 'SV-VCFK-9X-000039'
  tag stig_id: 'VCFK-9X-000039'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  describe file('/etc/vmware-rhttpproxy/ssl/rui.key') do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'rhttpproxy' }
    its('group') { should cmp 'rhttpproxy' }
  end
end
