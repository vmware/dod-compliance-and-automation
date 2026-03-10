control 'UBTU-22-411010' do
  title 'Ubuntu 22.04 LTS must prevent direct login into the root account.'
  desc 'To ensure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the Unix OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the Unix and Windows operating systems offer a "switch user" capability allowing users to authenticate with their individual credentials and, when needed, "switch" to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the operating system without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.'
  desc 'check', 'Verify Ubuntu 22.04 LTS prevents direct logins to the root account by using the following command:

     $ sudo passwd -S root
     root L 08/09/2022 0 99999 7 -1

If the output does not contain "L" in the second field to indicate the account is locked, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to prevent direct logins to the root account by using the following command:

     $ sudo passwd -l root'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64271r953437_chk'
  tag severity: 'medium'
  tag gid: 'V-260542'
  tag rid: 'SV-260542r1015006_rule'
  tag stig_id: 'UBTU-22-411010'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-64179r953438_fix'
  tag 'documentable'
  tag cci: ['CCI-000770', 'CCI-004045']
  tag nist: ['IA-2 (5)']

  describe command('sudo passwd -S root') do
    its('stdout.strip') { should match /^root\s+L\s+.*$/ }
  end
end
