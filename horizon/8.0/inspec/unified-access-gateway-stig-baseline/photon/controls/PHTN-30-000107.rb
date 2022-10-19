control 'PHTN-30-000107' do
  title 'The Photon operating system must send TCP timestamps.'
  desc  'TCP timestamps are used to provide protection against wrapped sequence numbers. It is possible to calculate system uptime (and boot time) by analyzing TCP timestamps. These calculated uptimes can help a bad actor in determining likely patch levels for vulnerabilities.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # /sbin/sysctl -a --pattern \"net.ipv4.tcp_timestamps$\"

    Expected result:

    net.ipv4.tcp_timestamps = 1

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s):

    # sed -i -e \"/^net.ipv4.tcp_timestamps/d\" /etc/sysctl.conf
    # echo net.ipv4.tcp_timestamps=1>>/etc/sysctl.conf
    # /sbin/sysctl --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000107'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.tcp_timestamps') do
    its('value') { should eq 1 }
  end
end
