control 'PHTN-50-000245' do
  title 'The Photon operating system must mount /tmp securely.'
  desc  "
    The \"noexec\" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

    The \"nodev\" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

    The \"nosuid\" mount option causes the system to not execute \"setuid\" and \"setgid\" files with owner privileges. This option must be used for mounting any file system not containing approved \"setuid\" and \"setguid\" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
  "
  desc  'rationale', ''
  desc  'check', "
    This is not applicable to the following VCF components: vCenter Server.

    At the command line, run the following command to verify the /tmp directory is mounted securely:

    # grep -w tmp /proc/mounts | awk '{print $(NF-2)}'

    Example result:

    rw,nosuid,nodev,noexec,size=8185412k,nr_inodes=1048576

    If no results are displayed, this is not a finding.

    If \"noexec\",\"nodev\", and \"nosuid\" are not all present, this is a finding.
  "
  desc 'fix', "
    Perform the steps below to override the tmp.mount settings.

    At the command line, run:

    # systemctl cat tmp.mount

    In the output, under the \"[Mount]\" heading, copy the \"Options\" line, for example:

    [Mount]
    ...
    Options=mode=1777,strictatime,nosuid,nodev,size=50%,nr_inodes=1m

    Run the following command to create or edit an override file:

    # systemctl edit tmp.mount

    Copy the \"Options\" line from before, as well as the \"[Mount]\" header and paste them in the space between the two relevant comment lines. For example:

    ### Anything between here and the comment below will become the new contents of the file
    [Mount]
    Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%,nr_inodes=1m
    ### Lines below this comment will be discarded

    Make sure to append any of the missing 'nosuid', 'nodev', or 'noexec' options delimited by commas.

    Restart the system for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000245'
  tag rid: 'SV-PHTN-50-000245'
  tag stig_id: 'PHTN-50-000245'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  tmpoptions = ['nosuid', 'noexec', 'nodev']

  result = command("grep -w tmp /proc/mounts | awk '{print $(NF-2)}'")

  if !result.stdout.empty?
    describe "Checking /tmp mount options - #{result.stdout.strip}" do
      subject { result.stdout.strip.split(',') }
      it { should include(*tmpoptions) }
    end
  else
    describe 'No tmp drive mounted...skipping' do
      skip 'No tmp drive mounted...skipping'
    end
  end
end
