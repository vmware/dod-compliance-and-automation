control "PHTN-10-000108" do
  title "The Photon operating system must not send IPv4 Internet Control
Message Protocol (ICMP) redirects."
  desc  "ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages contain
information from the system's route table, possibly revealing portions of the
network topology."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000108"
  tag stig_id: "PHTN-10-000108"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# /sbin/sysctl -a --pattern \"net.ipv4.conf.(all|default|eth.*).send_redirects\"

Expected result:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0

If the output does not match the expected result, this is a finding.

Note: The number of ethx lines returned is dependant on the number of
interfaces. Every ethx entry must be set to 0."
  desc 'fix', "At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern
\"net.ipv4.conf.(all|default|eth.*).send_redirects\"); do sed -i -e
\"/^${SETTING}/d\" /etc/sysctl.conf;echo $SETTING=0>>/etc/sysctl.conf; done"

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.send_redirects') do
    its('value') { should eq 0 }
  end

end

