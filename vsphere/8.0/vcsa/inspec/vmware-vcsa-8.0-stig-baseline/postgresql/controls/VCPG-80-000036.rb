control 'VCPG-80-000036' do
  title 'The vCenter PostgreSQL service must require authentication on all connections.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.'
  desc 'check', %q(At the command prompt, run the following command:

# grep -v "^#" /storage/db/vpostgres/pg_hba.conf |grep '\S'

If any lines are returned contain "trust" or "password" as an auth-method, this is a finding.)
  desc 'fix', 'Navigate to and open:

/storage/db/vpostgres/pg_hba.conf

Find and update any line that has a method of "trust" or "password" in the far-right column.

A correct, typical line will look like the below:

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local       VCDB               vpxd                                            peer map=vcdb

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres'
  impact 0.5
  tag check_id: 'C-62915r935427_chk'
  tag severity: 'medium'
  tag gid: 'V-259175'
  tag rid: 'SV-259175r935429_rule'
  tag stig_id: 'VCPG-80-000036'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-62824r935428_fix'
  tag satisfies: ['SRG-APP-000148-DB-000103', 'SRG-APP-000172-DB-000075']
  tag cci: ['CCI-000197', 'CCI-000764']
  tag nist: ['IA-5 (1) (c)', 'IA-2']

  describe postgres_hba_conf("#{input('pg_data_dir')}pg_hba.conf").where { type == 'local' } do
    its('auth_method') { should_not be_in ['trust', 'password'] }
  end
  describe postgres_hba_conf("#{input('pg_data_dir')}pg_hba.conf").where { type == 'host' } do
    its('auth_method') { should_not be_in ['trust', 'password'] }
  end
end
