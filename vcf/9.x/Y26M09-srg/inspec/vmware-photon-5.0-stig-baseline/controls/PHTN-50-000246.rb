control 'PHTN-50-000246' do
  title 'The Photon operating system must restrict core dumps.'
  desc  'By enabling the fs.suid_dumpable kernel parameter, core dumps are not generated for setuid or otherwise protected/tainted binaries. This prevents users from potentially accessing core dumps with privileged information they would otherwise not have access to read.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify core dumps are restricted:

    # /sbin/sysctl fs.suid_dumpable

    Example result:

    fs.suid_dumpable = 0

    If the \"fs.suid_dumpable\" kernel parameter is set to \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/sysctl.d/zz-stig-hardening.conf

    Add or update the following line:

    fs.suid_dumpable = 0

    Note: 0 is recommended for normal operation. If core dumps need to be captured for troubleshooting purposes then 2 is also an acceptable value.

    At the command line, run the following command to load the new configuration:

    # /sbin/sysctl --load /etc/sysctl.d/zz-stig-hardening.conf

    Note: If the file zz-stig-hardening.conf does not exist it must be created.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000246'
  tag rid: 'SV-PHTN-50-000246'
  tag stig_id: 'PHTN-50-000246'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should eq(0).or eq(2) }
  end
end
