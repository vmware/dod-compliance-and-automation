control 'UBTU-24-600190' do
  title 'Ubuntu 24.04 LTS must be configured to use TCP syncookies.'
  desc 'Denial of service (DoS) occurs when a resource is not available for legitimate users, resulting in the organization not being able to accomplish its mission or causing it to operate at degraded capacity.

Managing excess capacity ensures sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to use TCP syncookies with the following command:

$ sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1

If the value is not "1", this is a finding.

Check the saved value of TCP syncookies with the following command:

$ sudo grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null
/etc/sysctl.d/99-sysctl.conf:net.ipv4.tcp_syncookies=1
/etc/sysctl.conf:net.ipv4.tcp_syncookies=1

If the "net.ipv4.tcp_syncookies" option is not set to "1", is commented out, or is missing, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 24.04 LTS to use TCP syncookies with the following command:

$ sudo sysctl -w net.ipv4.tcp_syncookies=1

If "1" is not the system's default value, add or update the following line in "/etc/sysctl.conf":

net.ipv4.tcp_syncookies = 1)
  impact 0.5
  tag check_id: 'C-74786r1066746_chk'
  tag severity: 'medium'
  tag gid: 'V-270753'
  tag rid: 'SV-270753r1066748_rule'
  tag stig_id: 'UBTU-24-600190'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-74687r1066747_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp 1 }
  end

  sysctl_files = command('find /etc/sysctl.conf /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d -type f 2>/dev/null').stdout.split("\n")

  sysctl_files.each do |file_path|
    describe file(file_path) do
      its('content') { should match(/net\.ipv4\.tcp_syncookies\s*=\s*1/) }
    end
  end
end
