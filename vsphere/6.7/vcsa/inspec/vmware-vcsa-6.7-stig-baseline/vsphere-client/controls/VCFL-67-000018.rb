control 'VCFL-67-000018' do
  title "vSphere Client must ensure appropriate permissions are set on the
keystore."
  desc  "The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients. By gaining access to the
private key, an attacker can pretend to be an authorized server and decrypt the
SSL traffic between a client and the web server.

    vSphere Client pulls the machine certificate from the VECS keystore and
stores it in keystore.jks so Tomcat can access it. The minimum permissions and
ownership on the keystore are set by default but must be verified.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c \"%n permissions are %a and is owned by %U:%G\"
/etc/vmware/vsphere-client/keystore.jks

    Expected result:

    /etc/vmware/vsphere-client/keystore.jks permissions are 640 and is owned by
vsphere-client:users

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # chmod 640 /etc/vmware/vsphere-client/keystore.jks
    # chown vsphere-client:users /etc/vmware/vsphere-client/keystore.jks
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-239759'
  tag rid: 'SV-239759r679504_rule'
  tag stig_id: 'VCFL-67-000018'
  tag fix_id: 'F-42951r679503_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file('/etc/vmware/vsphere-client/keystore.jks') do
    its('mode') { should cmp '0640' }
    its('owner') { should eq 'vsphere-client' }
    its('group') { should eq 'users' }
  end
end
