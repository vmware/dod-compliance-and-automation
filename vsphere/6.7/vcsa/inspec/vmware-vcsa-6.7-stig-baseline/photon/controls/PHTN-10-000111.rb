control "PHTN-10-000111" do
  title "The Photon operating system must not perform multicast packet
forwarding."
  desc  "Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000111"
  tag stig_id: "PHTN-10-000111"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# /sbin/sysctl -a --pattern
\"net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding\"

Expected result:

net.ipv4.conf.all.mc_forwarding = 0
net.ipv4.conf.default.mc_forwarding = 0
net.ipv4.conf.eth0.mc_forwarding = 0
net.ipv6.conf.all.mc_forwarding = 0
net.ipv6.conf.default.mc_forwarding = 0
net.ipv6.conf.eth0.mc_forwarding = 0


If the output does not match the expected result, this is a finding.

Note: The number of ethx lines returned is dependant on the number of
interfaces. Every ethx entry must be set to 0."
  desc 'fix', "At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern
\"net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding\"); do sed -i -e
\"/^${SETTING}/d\" /etc/sysctl.conf;echo $SETTING=0>>/etc/sysctl.conf; done"

  describe kernel_parameter('net.ipv4.conf.all.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.all.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.default.mc_forwarding') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.eth0.mc_forwarding') do
    its('value') { should eq 0 }
  end

end

