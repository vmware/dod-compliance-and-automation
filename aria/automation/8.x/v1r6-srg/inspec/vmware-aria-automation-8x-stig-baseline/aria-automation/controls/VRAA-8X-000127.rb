control 'VRAA-8X-000127' do
  title 'The VMware Aria Automation Photon operating system must be configured so that all files have a valid owner and group owner.'
  desc  'If files do not have valid user and group owners, unintended access to files could occur.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \\; 2>/dev/null | grep -v \"/data/docker/\"

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command for each returned file:

    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRAA-8X-000127'
  tag rid: 'SV-VRAA-8X-000127'
  tag stig_id: 'VRAA-8X-000127'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  verbose = input('verbose')

  # If verbose is 'true' find and list (ls) all files with unknown owner/group
  if verbose
    cmd = command('find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \\; 2>/dev/null | grep -v "/data/docker/"').stdout
    # The resulting string should be empty
    describe 'The set of files with unknown owner or group' do
      subject { cmd }
      it { should cmp '' }
    end
  # If verbose is 'false' find all files with unknown owner/group and count them (wc)
  else
    cmd = command('find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \\; 2>/dev/null | grep -v "/data/docker/" | wc -l').stdout.to_i
    # The length of the result set should be 0
    describe 'The count of files with unknown owner or group' do
      subject { cmd }
      it { should cmp 0 }
    end
  end
end
