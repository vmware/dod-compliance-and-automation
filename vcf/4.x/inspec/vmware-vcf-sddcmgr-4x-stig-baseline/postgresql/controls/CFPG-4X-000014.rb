control 'CFPG-4X-000014' do
  title 'The SDDC Manager PostgreSQL service must be require authentication on all connections.'
  desc  "
    To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

    Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

    (i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
    (ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -v \"^#\" /data/pgdata/pg_hba.conf|grep -z --color=always \"trust\"

    If any lines are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /data/pgdata/pg_hba.conf

    Find and remove the line that has a method of \"trust\", in the far right column.

    A correct, typical line will look like the below:

    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    host       all                        all                 127.0.0.1/32           md5
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag satisfies: ['SRG-APP-000172-DB-000075', 'SRG-APP-000442-DB-000379']
  tag gid: 'V-CFPG-4X-000014'
  tag rid: 'SV-CFPG-4X-000014'
  tag stig_id: 'CFPG-4X-000014'
  tag cci: ['CCI-000197', 'CCI-000764', 'CCI-002422']
  tag nist: ['IA-2', 'IA-5 (1) (c)', 'SC-8 (2)']

  describe postgres_hba_conf("#{input('pg_install_dir')}/pg_hba.conf").where { type == 'local' } do
    its('auth_method') { should_not include 'trust' }
  end

  describe postgres_hba_conf("#{input('pg_install_dir')}/pg_hba.conf").where { type == 'host' } do
    its('auth_method') { should_not include 'trust' }
  end
end
