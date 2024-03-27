control 'CFLM-4X-000001' do
  title 'The SDDC Manager LCM service must enabled to generate service runtime logs.'
  desc  "
    Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

    Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time.

    Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep logging.config /opt/vmware/vcf/lcm/lcm-app/conf/application.properties

    Expected result:

    logging.config=classpath:logback-prod.xml

    If the output does not match the expected result or is commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application.properties

    Add or edit the following line to match below:

    logging.config=classpath:logback-prod.xml

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFLM-4X-000001'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3']

  describe parse_config_file(input('applicationPropertiesPath')) do
    its(['logging.config']) { should cmp 'classpath:logback-prod.xml' }
  end
end
