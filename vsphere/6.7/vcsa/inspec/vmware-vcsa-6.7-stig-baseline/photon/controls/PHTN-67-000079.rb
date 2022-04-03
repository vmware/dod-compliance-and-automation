control 'PHTN-67-000079' do
  title "The Photon operating system must ensure root $PATH entries are
appropriate."
  desc  "The $PATH variable contains a semicolon-delimited set of directories
that allows root to not specify the full path for a limited set of binaries.
Having unexpected directories in $PATH can lead to root running a binary other
than the one intended."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # echo $PATH

    Expected result:


/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/java/jre-vmware/bin:/opt/vmware/bin

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # export
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/java/jre-vmware/bin:/opt/vmware/bin
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239150'
  tag rid: 'SV-239150r675258_rule'
  tag stig_id: 'PHTN-67-000079'
  tag fix_id: 'F-42320r675257_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('echo $PATH') do
    its('stdout.strip') { should cmp '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/java/jre-vmware/bin:/opt/vmware/bin' }
  end
end
