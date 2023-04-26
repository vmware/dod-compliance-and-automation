control 'PHTN-40-000231' do
  title 'The Photon operating system must not perform IPv4 packet forwarding.'
  desc  'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc  'rationale', ''
  desc  'check', "
    If IP forwarding is required such as if Kubernetes is installed, this is Not Applicable.

    At the command line, run the following command to verify packet forwarding it disabled:

    # /sbin/sysctl net.ipv4.ip_forward

    Expected result:

    net.ipv4.ip_forward = 0

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.conf

    Add or update the following line:

    net.ipv4.ip_forward = 0

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load

    Note: If the file sysctl.conf doesn't exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-40-000231'
  tag rid: 'SV-PHTN-40-000231'
  tag stig_id: 'PHTN-40-000231'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should cmp 0 }
  end
end
