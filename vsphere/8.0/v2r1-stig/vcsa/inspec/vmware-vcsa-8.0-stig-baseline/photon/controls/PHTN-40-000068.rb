control 'PHTN-40-000068' do
  title 'The Photon operating system must be configured to use TCP syncookies.'
  desc "A TCP SYN flood attack can cause a Denial of Service (DOS) by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected and enables the system to continue servicing valid connection requests."
  desc 'check', 'At the command line, run the following command to verify TCP syncookies are enabled:

# /sbin/sysctl net.ipv4.tcp_syncookies

Example result:

net.ipv4.tcp_syncookies = 1

If "net.ipv4.tcp_syncookies" is not set to "1", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following line:

net.ipv4.tcp_syncookies = 1

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62569r933546_chk'
  tag severity: 'medium'
  tag gid: 'V-258829'
  tag rid: 'SV-258829r958528_rule'
  tag stig_id: 'PHTN-40-000068'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-62478r933547_fix'
  tag satisfies: ['SRG-OS-000142-GPOS-00071', 'SRG-OS-000420-GPOS-00186']
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp 1 }
  end
end
