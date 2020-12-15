# encoding: UTF-8

control 'V-219330' do
  title 'The Ubuntu operating system must be configured to use TCP syncookies.'
  desc  "DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    Managing excess capacity ensures that sufficient capacity is available to
counter flooding attacks. Employing increased capacity and service redundancy
may reduce the susceptibility to some DoS attacks. Managing excess capacity may
include, for example, establishing selected usage priorities, quotas, or
partitioning.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system is configured to use TCP syncookies.

    Check the value of TCP syncookies with the following command:

    # sysctl net.ipv4.tcp_syncookies
    net.ipv4.tcp_syncookies = 1

    If the value is not \"1\", this is a finding.

    Check the saved value of TCP syncookies with the following command:

    # sudo grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* |
grep -v '#'

    If no output is returned, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to use TCP syncookies, by running the
following command:

    # sudo sysctl -w net.ipv4.tcp_syncookies=1

    If \"1\" is not the system's default value then add or update the following
line in \"/etc/sysctl.conf\":

    net.ipv4.tcp_syncookies = 1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag gid: 'V-219330'
  tag rid: 'SV-219330r508662_rule'
  tag stig_id: 'UBTU-18-010500'
  tag fix_id: 'F-21054r305319_fix'
  tag cci: ['SV-109987', 'V-100883', 'CCI-001095']
  tag nist: ['SC-5 (2)']

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should cmp 1 }
  end
end

