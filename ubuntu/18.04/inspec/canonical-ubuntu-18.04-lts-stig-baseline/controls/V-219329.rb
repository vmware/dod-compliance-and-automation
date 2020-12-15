# encoding: UTF-8

control 'V-219329' do
  title "The Ubuntu operating system must provision temporary user accounts
with an expiration time of 72 hours or less."
  desc  "If temporary user accounts remain active when no longer needed or for
an excessive period, these accounts may be used to gain unauthorized access. To
mitigate this risk, automated termination of all temporary accounts must be set
upon account creation.

    Temporary accounts are established as part of normal account activation
procedures when there is a need for short-term accounts without the demand for
immediacy in account activation.

    If temporary accounts are used, the Ubuntu operating system must be
configured to automatically terminate these types of accounts after a
DoD-defined time period of 72 hours.

    To address access requirements, the Ubuntu operating system may be
integrated with enterprise-level authentication/access mechanisms that meet or
exceed access control policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system expires temporary user accounts within
72 hours or less.

    For every existing temporary account, run the following command to obtain
its account expiration information.

    # sudo chage -l system_account_name | grep expires

    Password expires : Aug 07, 2019
    Account expires : Aug 07, 2019

    Verify each of these accounts has an expiration date set within 72 hours of
accounts' creation.
    If any temporary account does not expire within 72 hours of that account's
creation, this is a finding.
  "
  desc  'fix', "
    If a temporary account must be created configure the system to terminate
the account after a 72 hour time period with the following command to set an
expiration date on it. Substitute \"system_account_name\" with the account to
be created.

    # sudo chage -E $(date -d \"+3 days\" +%F) system_account_name
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag gid: 'V-219329'
  tag rid: 'SV-219329r508662_rule'
  tag stig_id: 'UBTU-18-010449'
  tag fix_id: 'F-21053r305316_fix'
  tag cci: ['SV-109985', 'V-100881', 'CCI-000016']
  tag nist: ['AC-2 (2)']

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

