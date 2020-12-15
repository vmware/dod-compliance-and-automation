# encoding: UTF-8

control 'V-219327' do
  title "The Ubuntu operating system must automatically remove or disable
emergency accounts after 72 hours."
  desc  "Emergency accounts are different from infrequently used accounts
(i.e., local logon accounts used by the organization's system administrators
when network or normal logon/access is not available). Infrequently used
accounts are not subject to automatic termination dates. Emergency accounts are
accounts created in response to crisis situations, usually for use by
maintenance personnel. The automatic expiration or disabling time period may be
extended as needed until the crisis is resolved; however, it must not be
extended indefinitely. A permanent account should be established for privileged
users who need long-term maintenance accounts."
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system expires emergency accounts within 72
hours or less.
    For every emergency account, run the following command to obtain its
account expiration information.

    # sudo chage -l account_name | grep expires

    Password expires : Aug 07, 2019
    Account expires : Aug 07, 2019

    Verify each of these accounts has an expiration date set within 72 hours of
accounts' creation.
    If any of these accounts do not expire within 72 hours of that account's
creation, this is a finding.
  "
  desc  'fix', "
    If an emergency account must be created, configure the system to terminate
the account after a 72 hour time period with the following command to set an
expiration date on it. Substitute \"account_name\" with the account to be
created.

    # sudo chage -E $(date -d \"+3 days\" +%F) account_name
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag gid: 'V-219327'
  tag rid: 'SV-219327r508662_rule'
  tag stig_id: 'UBTU-18-010447'
  tag fix_id: 'F-21051r305310_fix'
  tag cci: ['SV-109981', 'V-100877', 'CCI-001682']
  tag nist: ['AC-2 (2)']

  describe 'Manual verification required' do
    skip 'Manually verify if emergency account must be created
      the system must terminate the account after a 72 hour time period.'
  end

end

