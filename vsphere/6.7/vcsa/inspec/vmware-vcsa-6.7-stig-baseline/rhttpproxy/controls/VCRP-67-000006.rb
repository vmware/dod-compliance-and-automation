control "VCRP-67-000006" do
  title "rhttpproxy must have logging enabled."
  desc  "After a security incident has occurred, investigators will often
review log files to determine what happened. rhttpproxy must create logs upon
service start up in order to capture information relevant to investigations."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000093-WSR-000053"
  tag gid: nil
  tag rid: "VCRP-67-000006"
  tag stig_id: "VCRP-67-000006"
  tag cci: "CCI-001462"
  tag nist: ["AU-14 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/log/outputToFiles' /etc/vmware-rhttpproxy/config.xml

Expected result:

<outputToFiles>true</outputToFiles>

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <log> block and configure <outputToFiles> as follows:

<outputToFiles>true</outputToFiles>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/log/outputToFiles']) { should cmp ['true'] }
  end

end

