control 'HZNV-8X-000010' do
  title 'The Horizon Connection Server must be configured with an events database.'
  desc  "
    The Horizon Connection Server stores application level events and actions in a dedicated database rather than log files. This makes day-to-day administration easier while offloading these events to a separate system for resiliency.

    An events database is configured after Connection Server deployment. It only needs to be completed one time, even in the case of multiple grouped Connection Servers, as the configuration will be applied to the other servers automatically.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Monitor >> Events.

    If the right pane is empty or shows \"Events DB is not configured\", this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Event Configuration.

    In the right pane, under \"Event Database\", click \"Edit\" and enter the necessary database information in the fields provided.

    Click \"OK\".

    Note: Horizon Connection Server supports MSSQL and Oracle database types. Create a database with an appropriate, descriptive name. Create a user with permission to create tables, views, Oracle triggers and sequences (if Oracle) and permission to read from and write to these objects. Consult VMware documentation for more detailed database setup information and minimum required privileges.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-AS-000050'
  tag satisfies: ['SRG-APP-000091-AS-000052', 'SRG-APP-000095-AS-000056', 'SRG-APP-000096-AS-000059', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063', 'SRG-APP-000101-AS-000072', 'SRG-APP-000266-AS-000168', 'SRG-APP-000343-AS-000030', 'SRG-APP-000495-AS-000220', 'SRG-APP-000499-AS-000224', 'SRG-APP-000503-AS-000228', 'SRG-APP-000504-AS-000229', 'SRG-APP-000505-AS-000230', 'SRG-APP-000509-AS-000234']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000010'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001312', 'CCI-001487', 'CCI-002234']
  tag nist: ['AC-6 (9)', 'AU-12 a', 'AU-12 c', 'AU-3', 'AU-3 (1)', 'SI-11 a']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/EventDatabase/Get')

  evinfo = JSON.parse(result.stdout)

  describe evinfo do
    its(['eventDatabaseSet']) { should cmp true }
  end
end
