control 'PHTN-67-000122' do
  title 'The Photon operating system must set the UMASK parameter correctly.'
  desc  "The umask value influences the permissions assigned to files when they
are created. The umask setting in login.defs controls the permissions for a new
user's home directory. By setting the proper umask, home directories will only
allow the new user to read and write files there.


  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep UMASK /etc/login.defs

    Expected result:

    UMASK 077

    If the output does not match the expected result, this a finding.
  "
  desc 'fix', "
    Open /etc/login.defs with a text editor.

    Ensure that the \"UMASK\" line is uncommented and set to the following:

    UMASK 077
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag satisfies: ['SRG-OS-000480-GPOS-00228', 'SRG-OS-000480-GPOS-00230']
  tag gid: 'V-239193'
  tag rid: 'SV-239193r675387_rule'
  tag stig_id: 'PHTN-67-000122'
  tag fix_id: 'F-42363r675386_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('UMASK') { should cmp '077' }
  end
end
