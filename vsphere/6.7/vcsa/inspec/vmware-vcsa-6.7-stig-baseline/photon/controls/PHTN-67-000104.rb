control 'PHTN-67-000104' do
  title "The Photon operating system must not forward IPv4 or IPv6
source-routed packets."
  desc  "Source routing is an Internet Protocol (IP) mechanism that allows an
IP packet to carry information, a list of addresses, which tells a router the
path the packet must take. There is also an option to record the hops as the
route is traversed.

    The list of hops taken, the \"route record\", provides the destination with
a return path to the source. This allows the source (the sending host) to
specify the route, loosely or strictly, ignoring the routing tables of some or
all of the routers. It can allow a user to redirect network traffic for
malicious purposes and should therefore be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern
\"net.ipv[4|6].conf.(all|default|eth.*).accept_source_route\"

    Expected result:

    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    net.ipv4.conf.eth0.accept_source_route = 0
    net.ipv6.conf.all.accept_source_route = 0
    net.ipv6.conf.default.accept_source_route = 0
    net.ipv6.conf.eth0.accept_source_route = 0

    If the output does not match the expected result, this is a finding.

    Note: The number of \"ethx\" lines returned is dependent on the number of
interfaces. Every \"ethx\" entry must be set to \"0\".
  "
  desc 'fix', "
    Open /etc/sysctl.conf with a text editor.

    Add or update the following lines:

    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    net.ipv4.conf.eth0.accept_source_route = 0
    net.ipv6.conf.all.accept_source_route = 0
    net.ipv6.conf.default.accept_source_route = 0
    net.ipv6.conf.eth0.accept_source_route = 0

    Run the following command to load the new setting:

    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239175'
  tag rid: 'SV-239175r816656_rule'
  tag stig_id: 'PHTN-67-000104'
  tag fix_id: 'F-42345r816655_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv6.conf.eth0.accept_source_route') do
    its('value') { should eq 0 }
  end
end
