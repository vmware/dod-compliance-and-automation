control 'PHTN-50-000244' do
  title 'The Photon operating system must enable hardlink access control protection in the kernel.'
  desc  'By enabling the fs.protected_hardlinks kernel parameter, users can no longer create soft or hard links to files they do not own. Disallowing such hardlinks mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify hardlink protection is enabled:

    # /sbin/sysctl fs.protected_hardlinks

    Example result:

    fs.protected_hardlinks = 1

    If the \"fs.protected_hardlinks\" kernel parameter is not set to \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following line:

    fs.protected_hardlinks = 1

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000244'
  tag rid: 'SV-PHTN-50-000244'
  tag stig_id: 'PHTN-50-000244'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('fs.protected_hardlinks') do
    its('value') { should cmp 1 }
  end
end
