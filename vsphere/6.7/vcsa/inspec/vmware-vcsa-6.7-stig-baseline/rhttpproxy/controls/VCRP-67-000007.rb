control "VCRP-67-000007" do
  title "The rhttpproxy private key file must be owned by root and group owned
by root."
  desc  "rhttpproxy's private key is used to prove the identity of the server
to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the TLS traffic between a client and the web
server.
  "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000176-WSR-000096"
  tag gid: nil
  tag rid: "VCRP-67-000007"
  tag stig_id: "VCRP-67-000007"
  tag cci: "CCI-000186"
  tag nist: ["IA-5 (2) (b)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# stat -c \"%n permisions are %a, is owned by %U and group owned by %G\"
/etc/vmware-rhttpproxy/ssl/rui.key

Expected result:

/etc/vmware-rhttpproxy/ssl/rui.key permisions are 600, is owned by root and
group owned by root

If the output does not match the expected result, this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

# chown root:root /etc/vmware-rhttpproxy/ssl/rui.key
"

  describe file('/etc/vmware-rhttpproxy/ssl/rui.key') do
    its('mode') { should eq '0600'}
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end

end

