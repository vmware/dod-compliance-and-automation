control 'PHTN-30-000101' do
  title 'The Photon operating system must prevent IPv4 Internet Control Message Protocol (ICMP) secure redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'At the command line, run the following command:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default|eth.*).secure_redirects"

Expected result:

net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.eth0.secure_redirects = 0

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "0".'
  desc 'fix', 'At the command line, run the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern "net.ipv4.conf.(all|default|eth.*).secure_redirects"); do sed -i -e "/^${SETTING}/d" /etc/sysctl.conf;echo $SETTING=0>>/etc/sysctl.conf; done
# /sbin/sysctl --load'
  impact 0.5
  tag check_id: 'C-60245r887382_chk'
  tag severity: 'medium'
  tag gid: 'V-256570'
  tag rid: 'SV-256570r887384_rule'
  tag stig_id: 'PHTN-30-000101'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60188r887383_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.eth0.secure_redirects') do
    its('value') { should eq 0 }
  end
end
