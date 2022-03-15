control 'PHTN-67-000120' do
  title "The Photon operating system must protect all sysctl configuration
files from unauthorized access."
  desc  "The sysctl configuration file specifies values for kernel parameters
to be set on boot. Incorrect or malicious configuration of these parameters can
have a negative effect on system security."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # find /etc/sysctl.conf /etc/sysctl.d/* -xdev -type f -a '(' -not -perm 600
-o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following commands for each returned file:

    # chmod 600 <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239191'
  tag rid: 'SV-239191r675381_rule'
  tag stig_id: 'PHTN-67-000120'
  tag fix_id: 'F-42361r675380_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("find /etc/sysctl.conf /etc/sysctl.d/* -xdev -type f -a '(' -not -perm 600 -o -not -user root -o -not -group root ')' -exec ls -ld {} \;") do
    its('stdout') { should eq '' }
  end
end
