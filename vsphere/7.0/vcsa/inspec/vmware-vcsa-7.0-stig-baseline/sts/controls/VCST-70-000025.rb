# encoding: UTF-8

control 'VCST-70-000025' do
  title 'The Security Token Service must not enable support for TRACE requests.'
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server
and plug-ins or modules being used. When debugging or trace information is
enabled in a production web server, information about the web server, such as
web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage may be displayed.

    Since this information may be placed in logs and general messages during
normal operation of the web server, an attacker does not need to cause an error
condition to gain this information.

    The Security Token Service can be configured to set the debugging level. By
setting the debugging level to zero, no debugging information will be provided
to a malicious user.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep allowTrace /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    If \"allowTrace\" is set to \"true\", this is a finding.

    If no line is returned, this is NOT a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Locate and remove the 'allowTrace=\"true\"' setting.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000025'
  tag fix_id: nil
  tag cci: 'CCI-001312'
  tag nist: ['SI-11 a']

  describe.one do
    describe xml("#{input('serverXmlPath')}") do
      its(['Server/Service/Connector/attribute::allowTrace']) { should eq [] }
    end

    describe xml("#{input('serverXmlPath')}") do
      its(['Server/Service/Connector/attribute::allowTrace']) { should cmp "false" }
    end
  end

end

