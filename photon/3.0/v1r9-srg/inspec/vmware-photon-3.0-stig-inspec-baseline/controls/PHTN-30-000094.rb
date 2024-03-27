control 'PHTN-30-000094' do
  title 'The Photon operating system must be configured so that all files have a valid owner and group owner.'
  desc  'If files do not have valid user and group owners, unintended access to files could occur.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # find / -xdev -path /var/lib/containerd -prune -o \\( -nouser -o -nogroup \\) -exec ls -ld {} \\; 2>/dev/null

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command for each returned file:

    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-30-000094'
  tag rid: 'SV-PHTN-30-000094'
  tag stig_id: 'PHTN-30-000094'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  verbose = input('verbose')

  # Pull all supported local filesystems from /proc/filesystems
  results = command('grep -v "nodev" /proc/filesystems | awk \'NF{ print $NF }\'').stdout

  if !results.empty?
    results.strip.split("\n").each do |fs|
      # Collect the mount points of all mounted filesystems matching the type
      command("df -t #{fs} --output=target | tail +2").stdout.split("\n").each do |mp|
        # If verbose is 'true' find and list (ls) all files with unknown owner/group
        if verbose
          user_cmd = command("find #{mp} -xdev -fstype #{fs} -path /var/lib/containerd -prune -o -nouser -exec ls -ld {} \\; 2>/dev/null").stdout
          group_cmd = command("find #{mp} -xdev -fstype #{fs} -path /var/lib/containerd -prune -o -nogroup -exec ls -ld {} \\; 2>/dev/null").stdout
          # The resulting string should be empty
          describe "The set of files (#{fs}:#{mp}) with unknown owner" do
            subject { user_cmd }
            it { should cmp '' }
          end
          describe "The set of files (#{fs}:#{mp}) with unknown group owner" do
            subject { group_cmd }
            it { should cmp '' }
          end
        # If verbose is 'false' find all files with unknown owner/group and count them (wc)
        else
          user_cmd = command("find #{mp} -xdev -fstype #{fs} -path /var/lib/containerd -prune -o -nouser 2>/dev/null | wc -l").stdout.to_i
          group_cmd = command("find #{mp} -xdev -fstype #{fs} -path /var/lib/containerd -prune -o -nogroup 2>/dev/null | wc -l").stdout.to_i
          # The length of the result set should be 0
          describe "The set of files (#{fs}:#{mp}) with unknown owner" do
            subject { user_cmd }
            it { should cmp 0 }
          end
          describe "The set of files (#{fs}:#{mp}) with unknown group owner" do
            subject { group_cmd }
            it { should cmp 0 }
          end
        end
      end
    end
  else
    describe 'Command produced no local filesystems from /proc/filesystems. Troubleshoot and rerun.' do
      skip 'Command produced no local filesystems from /proc/filesystems. Troubleshoot and rerun.'
    end
  end
end
