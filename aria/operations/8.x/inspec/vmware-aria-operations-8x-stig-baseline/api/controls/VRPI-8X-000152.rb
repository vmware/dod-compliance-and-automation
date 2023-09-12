control 'VRPI-8X-000152' do
  title 'The API service must enable "ENFORCE_ENCODING_IN_GET_WRITER".'
  desc  'Some clients try to guess the character encoding of text media when the mandated default of ISO-8859-1 should be used. Some browsers will interpret as UTF-7 when the characters are safe for ISO-8859-1. This can create the potential for a XSS attack. To defend against this, enforce_encoding_in_get_writer must be set to true.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep ENFORCE_ENCODING_IN_GET_WRITER $CATALINA_BASE/conf/catalina.properties

    Example result:

    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true

    If the \"org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER\" setting does not exist, this is not a finding.

    If \"org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER\" exists and is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open the $CATALINA_BASE/conf/catalina.properties file.

    Update or remove the following line:

    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true

    Restart the service with the following command:

    # systemctl restart api.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRPI-8X-000152'
  tag rid: 'SV-VRPI-8X-000152'
  tag stig_id: 'VRPI-8X-000152'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file("#{input('api-catalinaPropsPath')}").params['org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER'] do
    it { should be_in [nil, 'true'] }
  end
end
