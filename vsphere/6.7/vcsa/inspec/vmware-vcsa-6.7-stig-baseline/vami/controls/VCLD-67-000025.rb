control "VCLD-67-000025" do
  title "VAMI must only allow authenticated system administrators to have
access to the keystore."
  desc  "The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.By gaining access to the
private key, an attacker can pretend to be an authorized server and decrypt the
SSL traffic between a client and the web server."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000176-WSR-000096"
  tag gid: nil
  tag rid: "VCLD-67-000025"
  tag stig_id: "VCLD-67-000025"
  tag cci: "CCI-000186"
  tag nist: ["IA-5 (2) (b)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

stat /etc/applmgmt/appliance/server.pem|grep Access

If the \"server.pem\" file is not owned by \"root\", group owned by \"root\" or
the file permissions are not \"600\", this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

chown root:root /etc/applmgmt/appliance/server.pem
chmod 600 /etc/applmgmt/appliance/server.pem"

  describe file('/etc/applmgmt/appliance/server.pem') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    its('mode') { should cmp '0600' }
  end

end

