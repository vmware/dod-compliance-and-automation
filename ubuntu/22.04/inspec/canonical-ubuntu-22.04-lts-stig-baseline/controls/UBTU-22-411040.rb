control 'UBTU-22-411040' do
  title 'Ubuntu 22.04 LTS must automatically expire temporary accounts within 72 hours.'
  desc 'Temporary accounts are privileged or nonprivileged accounts established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances, but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.

'
  desc 'check', "Verify temporary accounts have been provisioned with an expiration date of 72 hours by using the following command:

     $ sudo chage -l <temporary_account_name> | grep -E '(Password|Account) expires'
     Password expires     : Apr 1, 2024
     Account expires        : Apr 1, 2024

Verify each of these accounts has an expiration date set within 72 hours.

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding."
  desc 'fix', 'Configure Ubuntu 22.04 LTS to expire temporary accounts after 72 hours by using the following command:

     $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64277r953455_chk'
  tag severity: 'medium'
  tag gid: 'V-260548'
  tag rid: 'SV-260548r958364_rule'
  tag stig_id: 'UBTU-22-411040'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-64185r953456_fix'
  tag satisfies: ['SRG-OS-000002-GPOS-00002', 'SRG-OS-000123-GPOS-00064']
  tag 'documentable'
  tag cci: ['CCI-000016', 'CCI-001682']
  tag nist: ['AC-2 (2)', 'AC-2 (2)']

  temporary_accounts = input('temporary_accounts')

  if temporary_accounts.empty?
    describe 'Temporary accounts' do
      subject { temporary_accounts }
      it { should be_empty }
    end
  else
    temporary_accounts.each do |acct|
      describe command("chage -l #{acct} | grep 'Account expires'") do
        its('stdout.strip') { should_not match /:\s*never/ }
      end
    end
  end
end
