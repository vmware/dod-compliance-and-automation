control 'PSQL-00-000036' do
  title 'PostgreSQL must require authentication on all connections.'
  desc  "
    To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

    Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

    (i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
    (ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -v \"^#\" /data/pgdata/pg_hba.conf |grep '\\S'

    If any lines are returned contain \"trust\" or \"password\" as an auth-method, this is a finding.

    Note: Substitute the path for the location of your PostgreSQL hba configuration file.
  "
  desc 'fix', "
    Edit the pg_hba.conf  file for your installation and update the following options:

    Find and remove or update any line that has a method of \"trust\" or \"password\" in the far right column.

    A correct, typical line will look like the below:

    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    host       all                        all                 127.0.0.1/32           scram-sha-256

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag satisfies: ['SRG-APP-000172-DB-000075']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000036'
  tag cci: ['CCI-000764', 'CCI-000197']
  tag nist: ['IA-2', 'IA-5 (1) (c)']

  describe postgres_hba_conf("#{input('pg_data_dir')}pg_hba.conf").where { type == 'local' } do
    its('auth_method') { should_not be_in ['trust', 'password'] }
  end
  describe postgres_hba_conf("#{input('pg_data_dir')}pg_hba.conf").where { type == 'host' } do
    its('auth_method') { should_not be_in ['trust', 'password'] }
  end
end
