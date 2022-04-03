control 'PHTN-67-000082' do
  title "The Photon operating system must configure a secure umask for all
shells."
  desc  "A user's umask influences the permissions assigned to files that a
user creates. Setting an appropriate umask is important to make sure that
information is not exposed to unprivileged users."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # cat /etc/profile.d/umask.sh

    Expected result:

    # By default, the umask should be set.
    if [ \"$(id -gn)\" = \"$(id -un)\" -a $EUID -gt 99 ] ; then
      umask 002
    else
      umask 027
    fi

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/profile.d/umask.sh with a text editor.

    Set the contents as follows:

    # By default, the umask should be set.
    if [ \"$(id -gn)\" = \"$(id -un)\" -a $EUID -gt 99 ] ; then
      umask 002
    else
      umask 027
    fi
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239153'
  tag rid: 'SV-239153r675267_rule'
  tag stig_id: 'PHTN-67-000082'
  tag fix_id: 'F-42323r675266_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/profile.d/umask.sh') do
    its('content') { should match "# By default, the umask should be set.\nif [ \"$(id -gn)\" = \"$(id -un)\" -a $EUID -gt 99 ] ; then\n  umask 002\nelse\n  umask 027\nfi\n" }
    its('content') { should match 'umask 002' }
    its('content') { should match 'umask 027' }
  end
end
