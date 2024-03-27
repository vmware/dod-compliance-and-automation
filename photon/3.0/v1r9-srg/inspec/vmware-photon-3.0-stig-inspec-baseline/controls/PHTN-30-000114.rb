control 'PHTN-30-000114' do
  title 'The Photon operating system must set the "umask" parameter correctly.'
  desc  "The \"umask\" value influences the permissions assigned to files when they are created. The \"umask\" setting in \"login.defs\" controls the permissions for a new user's home directory. By setting the proper \"umask\", home directories will only allow the new user to read and write files there."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep ^UMASK /etc/login.defs

    Example result:

    UMASK 077

    If \"UMASK\" is not configured to \"077\", this a finding.

    Note: \"UMASK\" should only be specified once in login.defs.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/login.defs

    Ensure the \"UMASK\" line is uncommented and set to the following:

    UMASK 077
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag gid: 'V-PHTN-30-000114'
  tag rid: 'SV-PHTN-30-000114'
  tag stig_id: 'PHTN-30-000114'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('UMASK') { should cmp '077' }
  end
end
