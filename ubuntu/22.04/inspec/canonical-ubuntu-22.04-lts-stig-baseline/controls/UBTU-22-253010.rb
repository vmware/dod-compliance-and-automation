control 'UBTU-22-253010' do
  title 'Ubuntu 22.04 LTS must be configured to use TCP syncookies.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to use TCP syncookies by using the following command:

     $ sysctl net.ipv4.tcp_syncookies
     net.ipv4.tcp_syncookies = 1

If the value is not "1", this is a finding.

Check the saved value of TCP syncookies by using the following command:

     $ sudo grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null

If the "net.ipv4.tcp_syncookies" option is not set to "1", is commented out, or is missing, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 22.04 LTS to use TCP syncookies by using the following command:

     $ sudo sysctl -w net.ipv4.tcp_syncookies=1

If "1" is not the system's default value, add or update the following line in "/etc/sysctl.conf":

     net.ipv4.tcp_syncookies = 1)
  impact 0.5
  tag check_id: 'C-64251r953377_chk'
  tag severity: 'medium'
  tag gid: 'V-260522'
  tag rid: 'SV-260522r1069097_rule'
  tag stig_id: 'UBTU-22-253010'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-64159r1069096_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp 1 }
  end
end
