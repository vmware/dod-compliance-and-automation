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
  tag fix_id: nil
  tag cci: "CCI-000186"
  tag nist: ["IA-5 (2) (b)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "IA-5 (2) (b)"
  tag check: "At the command prompt, execute the following command:

# stat -c \"%n is owned by %U and group owned by %G\"
/etc/vmware-rhttpproxy/ssl/rui.key

If the key is not owned by root and group owned by root, this is a finding."
  tag fix: "At the command prompt, execute the following command:

# chown root:root /etc/vmware-rhttpproxy/ssl/rui.key
"

  describe file('/etc/vmware-rhttpproxy/ssl/rui.key') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end

end