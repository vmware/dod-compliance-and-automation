control "PHTN-10-000110" do
  title "The Photon operating system must use a reverse-path filter for IPv4
network traffic."
  desc  "Enabling reverse path filtering drops packets with source addresses
that should not have been able to be received on the interface they were
received on. It should not be used on systems which are routers for complicated
networks, but is helpful for end hosts and routers serving small networks."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000110"
  tag stig_id: "PHTN-10-000110"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# /sbin/sysctl -a --pattern \"net.ipv4.conf.(all|default|eth.*)\\.rp_filter\"

Expected result:

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.eth0.rp_filter = 1

If the output does not match the expected result, this is a finding.

Note: The number of ethx lines returned is dependant on the number of
interfaces. Every ethx entry must be set to 1."
  desc 'fix', "At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern
\"net.ipv4.conf.(all|default|eth.*)\\.rp_filter\"); do sed -i -e
\"/^${SETTING}/d\" /etc/sysctl.conf;echo $SETTING=1>>/etc/sysctl.conf; done"

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.rp_filter') do
    its('value') { should eq 1 }
  end

end

