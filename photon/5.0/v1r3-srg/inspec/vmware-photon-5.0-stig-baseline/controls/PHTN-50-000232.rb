control 'PHTN-50-000232' do
  title 'The Photon operating system must send TCP timestamps.'
  desc  'TCP timestamps are used to provide protection against wrapped sequence numbers. It is possible to calculate system uptime (and boot time) by analyzing TCP timestamps. These calculated uptimes can help a bad actor in determining likely patch levels for vulnerabilities.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify TCP timestamps are enabled:

    # /sbin/sysctl net.ipv4.tcp_timestamps

    Expected result:

    net.ipv4.tcp_timestamps = 1

    If the \"net.ipv4.tcp_timestamps\" kernel parameter is not set to \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following line:

    net.ipv4.tcp_timestamps = 1

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000232'
  tag rid: 'SV-PHTN-50-000232'
  tag stig_id: 'PHTN-50-000232'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.tcp_timestamps') do
    its('value') { should cmp 1 }
  end
end
