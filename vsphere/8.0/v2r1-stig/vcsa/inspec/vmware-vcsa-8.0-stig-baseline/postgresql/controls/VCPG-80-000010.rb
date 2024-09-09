control 'VCPG-80-000010' do
  title 'The vCenter PostgreSQL service must produce logs containing sufficient information to establish what type of events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_line_prefix;"

Expected result:

%m %c %x %d %u %r %p %l

If the output does not include each option in the expected result, this is a finding.'
  desc 'fix', 'A script is included with vCenter to generate a PostgreSQL STIG configuration.

At the command prompt, run the following commands:

# chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
# /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
# chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres'
  impact 0.5
  tag check_id: 'C-62911r935415_chk'
  tag severity: 'medium'
  tag gid: 'V-259171'
  tag rid: 'SV-259171r960891_rule'
  tag stig_id: 'VCPG-80-000010'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag fix_id: 'F-62820r935416_fix'
  tag satisfies: ['SRG-APP-000095-DB-000039', 'SRG-APP-000096-DB-000040', 'SRG-APP-000097-DB-000041', 'SRG-APP-000098-DB-000042', 'SRG-APP-000099-DB-000043', 'SRG-APP-000100-DB-000201', 'SRG-APP-000101-DB-000044', 'SRG-APP-000375-DB-000323']
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-001487', 'CCI-001889']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-3 f', 'AU-8 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW log_line_prefix;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp '%m %c %x %d %u %r %p %l' }
  end
end
