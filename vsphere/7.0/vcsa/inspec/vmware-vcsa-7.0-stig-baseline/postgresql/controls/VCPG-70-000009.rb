control 'VCPG-70-000009' do
  title 'VMware Postgres must require authentication on all connections.'
  desc  "
    To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

    VMware Postgres client authentication configuration is configured in pg_hba.conf. In this file are a number of lines that specify who can connect to the service, from where and using what authentication methods. In Postgres there is a concept of a trusted connection where a specific network mask can connect without any authentication, to any account. This connection is termed 'trust' in pg_hba.conf and it must not be present. Out of the box, VMware Postgres requires standard password authentication for all connections.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -v \"^#\" /storage/db/vpostgres/pg_hba.conf|grep -z --color=always \"trust\"

    If any lines are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /storage/db/pgdata/pg_hba.conf.

    Find and remove the line that has a method of \"trust\" in the far right column.

    A correct, typical line will look like the following:

    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    host       all                        all                 127.0.0.1/32           md5
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000009'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe postgres_hba_conf("#{input('pg_install_dir')}/pg_hba.conf").where { type == 'local' } do
    its('auth_method') { should_not include 'trust' }
  end

  describe postgres_hba_conf("#{input('pg_install_dir')}/pg_hba.conf").where { type == 'host' } do
    its('auth_method') { should_not include 'trust' }
  end
end
