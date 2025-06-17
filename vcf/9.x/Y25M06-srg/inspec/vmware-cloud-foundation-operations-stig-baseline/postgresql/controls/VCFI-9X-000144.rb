control 'VCFI-9X-000144' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must have log collection enabled.'
  desc  "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the PostgreSQL is running."
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'SHOW logging_collector;'\"

    Example result:

    on

    If the \"logging_collector\" setting is not configured to \"on\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET logging_collector TO 'on';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-VCFI-9X-000144'
  tag rid: 'SV-VCFI-9X-000144'
  tag stig_id: 'VCFI-9X-000144'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query('SHOW logging_collector;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
