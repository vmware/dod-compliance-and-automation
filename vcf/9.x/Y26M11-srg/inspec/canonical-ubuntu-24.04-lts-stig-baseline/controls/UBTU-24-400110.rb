control 'UBTU-24-400110' do
  title 'Ubuntu 24.04 LTS must prevent direct login to the root account.'
  desc 'To ensure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator are the Unix OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the Unix and Windows operating systems offer a "switch user" capability allowing users to authenticate with their individual credentials and, when needed, switch to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on Ubuntu 24.04 LTS without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.'
  desc 'check', 'Verify Ubuntu 24.04 LTS prevents direct logins to the root account with the following command:

$ sudo passwd -S root
root L 04/08/2024 0 99999 7 -1

If the output does not contain "L" in the second field to indicate the account is locked, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to prevent direct logins to the root account by performing the following operations:

$ sudo passwd -l root'
  impact 0.5
  tag check_id: 'C-74757r1066659_chk'
  tag severity: 'medium'
  tag gid: 'V-270724'
  tag rid: 'SV-270724r1066661_rule'
  tag stig_id: 'UBTU-24-400110'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-74658r1066660_fix'
  tag 'documentable'
  tag cci: ['CCI-004045']
  tag nist: ['IA-2 (5)']

  describe command('sudo passwd -S root') do
    its('stdout.strip') { should match(/^root\s+L\s+.*$/) }
  end
end
