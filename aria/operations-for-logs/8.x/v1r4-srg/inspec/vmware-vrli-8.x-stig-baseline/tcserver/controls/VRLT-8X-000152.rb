control 'VRLT-8X-000152' do
  title 'The VMware Aria Operations for Logs tc Server must set ENFORCE_ENCODING_IN_GET_WRITER to true.'
  desc  'Some clients try to guess the character encoding of text media when the mandated default of ISO-8859-1 should be used. Some browsers will interpret as UTF-7 when the characters are safe for ISO-8859-1. This can create the potential for a XSS attack. To defend against this, enforce_encoding_in_get_writer must be set to true.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -i ENFORCE_ENCODING /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    If there are no results, this is not a finding.

    If the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER is present and not set to true, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties file.

    Either remove or edit the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER setting. If present, ensure the value is set to true.

    EXAMPLE:
    ...
    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true
    ...

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRLT-8X-000152'
  tag rid: 'SV-VRLT-8X-000152'
  tag stig_id: 'VRLT-8X-000152'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # Check catalina.properties file
  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content).params['org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER']
  describe.one do
    describe props do
      it { should cmp true }
    end
    describe props do
      it { should cmp nil }
    end
  end
end
