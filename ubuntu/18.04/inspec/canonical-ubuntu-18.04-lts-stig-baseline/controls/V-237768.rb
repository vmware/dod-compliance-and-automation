# encoding: UTF-8

control 'V-237768' do
  title "All local interactive user home directories defined in the /etc/passwd
file must exist."
  desc  "If a local interactive user has a home directory defined that does not
exist, the user may be given access to the / directory as the current working
directory upon logon. This could create a Denial of Service (DoS) because the
user would not be able to access their logon configuration files, and it may
give them visibility to system files they normally would not be able to access."
  desc  'rationale', ''
  desc  'check', "
    Verify the assigned home directory of all local interactive users on the
Ubuntu operating system exists.

    Check the home directory assignment for all local interactive
non-privileged users with the following command:

    $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

    smithj 1001 /home/smithj

    Note: This may miss interactive users that have been assigned a privileged
User ID (UID). Evidence of interactive use may be obtained from a number of log
files containing system logon information.

    Check that all referenced home directories exist with the following command:

    $ sudo pwck -r

    user 'smithj': directory '/home/smithj' does not exist

    If any home directories referenced in \"/etc/passwd\" are returned as not
defined, this is a finding.
  "
  desc  'fix', "
    Create home directories to all local interactive users that currently do
not have a home directory assigned. Use the following commands to create the
user home directory assigned in \"/etc/ passwd\":

    Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\", a User ID (UID) of \"smithj\", and a Group Identifier (GID)
of \"users assigned\" in \"/etc/passwd\".

    $ sudo mkdir /home/smithj
    $ sudo chown smithj /home/smithj
    $ sudo chgrp users /home/smithj
    $ sudo chmod 0750 /home/smithj
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-237768'
  tag rid: 'SV-237768r648736_rule'
  tag stig_id: 'UBTU-18-010450'
  tag fix_id: 'F-40941r648735_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']

  interactive_users = passwd.where { uid.to_i >= 1000 && shell !~ /nologin/ }
  pwck_output=command('pwck -r').stdout
  
  interactive_users.homes.each do |dir|
    describe(pwck_output) do
      it { should_not include dir }
    end
  end
end

