control 'VCST-80-000152' do
  title 'The vCenter STS service must enable "ENFORCE_ENCODING_IN_GET_WRITER".'
  desc 'Some clients try to guess the character encoding of text media when the mandated default of ISO-8859-1 should be used. Some browsers will interpret as UTF-7 when the characters are safe for ISO-8859-1. This can create the potential for a XSS attack. To defend against this, enforce_encoding_in_get_writer must be set to true.'
  desc 'check', 'At the command line, run the following command:

# grep ENFORCE_ENCODING_IN_GET_WRITER /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Example result:

org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true

If "org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER" is not set to "true", this is a finding.

If the "org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER" setting does not exist, this is not a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Update or remove the following line:

org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62740r934656_chk'
  tag severity: 'medium'
  tag gid: 'V-259000'
  tag rid: 'SV-259000r961863_rule'
  tag stig_id: 'VCST-80-000152'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-62649r934657_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER'] do
    it { should be_in [nil, 'true'] }
  end
end
