control 'VLIA-8X-000003' do
  title 'VMware Aria Operations for Logs must initiate session auditing upon startup.'
  desc  'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information which is only available if auditing is enabled before a given process is created.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format --xpath '/config/logging/configuration/loggers/logger[@name=\"com.vmware.loginsight.web.bootstrap.Bootstrapper.audit\"]' /usr/lib/loginsight/application/etc/loginsight-config-base.xml

    Expected result:

    <logger name=\"com.vmware.loginsight.web.bootstrap.Bootstrapper.audit\" level=\"info\" additivity=\"false\"><appenderRef ref=\"AUDIT\"/></logger>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/loginsight-config-base.xml

    Navigate to the <config>/<logging>/<configuration>/<loggers> section.

    Add or update the following logger and parameters to match below:

    <logger name=\"com.vmware.loginsight.web.bootstrap.Bootstrapper.audit\" level=\"info\" additivity=\"false\"><appenderRef ref=\"AUDIT\"/></logger>
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000092-AU-000670'
  tag gid: 'V-VLIA-8X-000003'
  tag rid: 'SV-VLIA-8X-000003'
  tag stig_id: 'VLIA-8X-000003'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
  tag mitigations: 'We have a prioritized feature request to implement this in the near term. .'

  xmlconf = xml("#{input('configBase')}")

  describe xmlconf do
    its(["//config/logging/configuration/loggers/logger[@name='com.vmware.loginsight.web.bootstrap.Bootstrapper.audit']/@level"]) { should cmp ['info'] }
    its(["//config/logging/configuration/loggers/logger[@name='com.vmware.loginsight.web.bootstrap.Bootstrapper.audit']/appenderRef/@ref"]) { should cmp ['AUDIT'] }
  end
end
