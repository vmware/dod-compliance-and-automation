control 'PHTN-40-000225' do
  title 'The Photon operating system must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'At the command line, run the following command to verify ICMP redirects are not accepted:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).accept_redirects"

Expected result:

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

If the "accept_redirects" kernel parameters are not set to "0", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following lines:

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62628r933723_chk'
  tag severity: 'medium'
  tag gid: 'V-258888'
  tag rid: 'SV-258888r991589_rule'
  tag stig_id: 'PHTN-40-000225'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62537r933724_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should cmp 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should cmp 0 }
  end
end
