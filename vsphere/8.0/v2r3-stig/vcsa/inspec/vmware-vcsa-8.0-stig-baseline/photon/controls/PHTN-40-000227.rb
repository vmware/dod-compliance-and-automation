control 'PHTN-40-000227' do
  title 'The Photon operating system must not send IPv4 Internet Control Message Protocol (ICMP) redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology."
  desc 'check', 'At the command line, run the following command to verify ICMP send redirects are not accepted:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default).send_redirects"

Expected result:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

If the "send_redirects" kernel parameters are not set to "0", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following lines:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62630r933729_chk'
  tag severity: 'medium'
  tag gid: 'V-258890'
  tag rid: 'SV-258890r991589_rule'
  tag stig_id: 'PHTN-40-000227'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62539r933730_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should cmp 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should cmp 0 }
  end
end
