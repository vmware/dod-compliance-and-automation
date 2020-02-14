control "VCRP-67-000004" do
  title "rhttpproxy must use cryptography to protect the integrity of remote
sessions."
  desc  "rhttpproxy supports TLS 1.0, 1.1 and 1.2 and can be configured to
support any combination thereof. Due to intrinsic problems in TLS 1.0 and 1.1
they must  be disabled and TLS 1.2 must be the only procotol supported for
client connections. "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000015-WSR-000014"
  tag gid: nil
  tag rid: "VCRP-67-000004"
  tag stig_id: "VCRP-67-000004"
  tag cci: "CCI-001453"
  tag nist: ["AC-17 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/vmacore/ssl/protocols'
/etc/vmware-rhttpproxy/config.xml

Expected result:

<protocols>tls1.2</protocols>

If there is no output, this is NOT a finding.

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <ssl> block inside of the <vmacore> block and configure <protocols>
as follows:

<protocols>tls1.2</protocols>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/vmacore/ssl/protocols']) { should cmp ['tls1.2'] }
  end

end

