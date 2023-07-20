control 'CFCS-5X-000014' do
  title 'The SDDC Manager Common Services service must produce log records containing information to establish what type of events occurred.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis.  Without being able to establish what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible.

    Log record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Application servers must log all relevant log data that pertains to the application server.  Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD/Web server activity, and application server-related system process activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep logging.config /opt/vmware/vcf/commonsvcs/conf/application.properties

    Expected result:

    logging.config=classpath:logback-${spring.profiles.active}.xml

    If the output does not match the expected result or is commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/commonsvcs/conf/application.properties

    Add or edit the following line to match below:

    logging.config=classpath:logback-${spring.profiles.active}.xml

    Restart the service for the setting to take effect.

    # systemctl restart commonsvcs.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag satisfies: ['SRG-APP-000092-AS-000053', 'SRG-APP-000096-AS-000059', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063']
  tag gid: 'V-CFCS-5X-000014'
  tag rid: 'SV-CFCS-5X-000014'
  tag stig_id: 'CFCS-5X-000014'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001464', 'CCI-001487']
  tag nist: ['AU-14 (1)', 'AU-3']

  describe parse_config_file(input('applicationPropertiesPath')) do
    its(['logging.config']) { should cmp 'classpath:logback-${spring.profiles.active}.xml' }
  end
end
