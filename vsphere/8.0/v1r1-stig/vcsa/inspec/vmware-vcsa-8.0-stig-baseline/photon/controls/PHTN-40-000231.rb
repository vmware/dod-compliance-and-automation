control 'PHTN-40-000231' do
  title 'The Photon operating system must not perform IPv4 packet forwarding.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'If IP forwarding is required, for example if Kubernetes is installed, this is Not Applicable.

At the command line, run the following command to verify packet forwarding it disabled:

# /sbin/sysctl net.ipv4.ip_forward

Expected result:

net.ipv4.ip_forward = 0

If the "net.ipv4.ip_forward" kernel parameter is not set to "0", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/sysctl.d/zz-stig-hardening.conf

Add or update the following line:

net.ipv4.ip_forward = 0

At the command line, run the following command to load the new configuration:

# /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

Note: If the file zz-stig-hardening.conf does not exist, it must be created.'
  impact 0.5
  tag check_id: 'C-62633r933738_chk'
  tag severity: 'medium'
  tag gid: 'V-258893'
  tag rid: 'SV-258893r933740_rule'
  tag stig_id: 'PHTN-40-000231'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62542r933739_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should cmp 0 }
  end
end
