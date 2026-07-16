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

    # grep '^Options' /lib/systemd/system/tmp.mount

    Example result:

    Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%%,nr_inodes=1m

    If \"noexec\",\"nodev\", and \"nosuid\" are not present, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /lib/systemd/system/tmp.mount

    Add or update the required settings on the \"Options\" line, for example:

    Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%%,nr_inodes=1m

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
  describe parse_config_file('/lib/systemd/system/tmp.mount').params['Mount'].Options.split(',') do
    it { should include(*tmpoptions) }
  end
end
