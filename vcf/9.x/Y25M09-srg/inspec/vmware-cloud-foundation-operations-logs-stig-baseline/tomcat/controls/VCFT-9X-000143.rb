control 'VCFT-9X-000143' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must enable "ENFORCE_ENCODING_IN_GET_WRITER".'
  desc  'Some clients try to guess the character encoding of text media when the mandated default of ISO-8859-1 should be used. Some browsers will interpret as UTF-7 when the characters are safe for ISO-8859-1. This can create the potential for a XSS attack. To defend against this, enforce_encoding_in_get_writer must be set to true.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # grep ENFORCE_ENCODING_IN_GET_WRITER /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Example result:

    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true

    If \"org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER\" is not set to \"true\", this is a finding.

    If the \"org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER\" setting does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Update or remove the following line:

    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCFT-9X-000143'
  tag rid: 'SV-VCFT-9X-000143'
  tag stig_id: 'VCFT-9X-000143'
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
