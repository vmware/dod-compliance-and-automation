control 'PHTN-40-000068' do
  title 'The Photon operating system must be configured to use TCP syncookies.'
  desc  "A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected and enables the system to continue servicing valid connection requests."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify TCP syncookies are enabled:

    # /sbin/sysctl net.ipv4.tcp_syncookies

    Expected result:

    net.ipv4.tcp_syncookies = 1

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.conf

    Add or update the following line:

    net.ipv4.tcp_syncookies = 1

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load

    Note: If the file sysctl.conf doesn't exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag satisfies: ['SRG-OS-000420-GPOS-00186']
  tag gid: 'V-PHTN-40-000068'
  tag rid: 'SV-PHTN-40-000068'
  tag stig_id: 'PHTN-40-000068'
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5', 'SC-5 (2)']

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp 1 }
  end
end
