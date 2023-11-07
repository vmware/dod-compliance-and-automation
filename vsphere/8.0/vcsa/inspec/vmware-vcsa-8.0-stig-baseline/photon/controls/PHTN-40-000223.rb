control 'PHTN-40-000223' do
  title 'The Photon operating system must not forward IPv4 or IPv6 source-routed packets.'
  desc 'Source routing is an Internet Protocol mechanism that allows an IP packet to carry information, a list of addresses, that tells a router the path the packet must take. There is also an option to record the hops as the route is traversed.

The list of hops taken, the "route record", provides the destination with a return path to the source. This allows the source (the sending host) to specify the route, loosely or strictly, ignoring the routing tables of some or all of the routers. It can allow a user to redirect network traffic for malicious purposes and should therefore be disabled.'
  desc 'check', 'At the command line, run the following command to verify source-routed packets are not forwarded:

# /sbin/sysctl -a --pattern "net.ipv[4|6].conf.(all|default).accept_source_route"

Expected result:

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

If the "accept_source_route" kernel parameters are not set to "0", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following lines:

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62626r933717_chk'
  tag severity: 'medium'
  tag gid: 'V-258886'
  tag rid: 'SV-258886r933719_rule'
  tag stig_id: 'PHTN-40-000223'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62535r933718_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should cmp 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should cmp 0 }
  end
  describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
    its('value') { should cmp 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_source_route') do
    its('value') { should cmp 0 }
  end
end
