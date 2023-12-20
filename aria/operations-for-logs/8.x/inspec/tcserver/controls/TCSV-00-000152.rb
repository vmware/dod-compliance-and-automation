control 'TCSV-00-000152' do
  title 'ENFORCE_ENCODING_IN_GET_WRITER must be set to true.'
  desc  'Some clients try to guess the character encoding of text media when the mandated default of ISO-8859-1 should be used. Some browsers will interpret as UTF-7 when the characters are safe for ISO-8859-1. This can create the potential for a XSS attack. To defend against this, enforce_encoding_in_get_writer must be set to true.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -i ENFORCE_ENCODING $CATALINA_BASE/conf/catalina.properties

    If there are no results, or if the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER is not set to true, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/catalina.properties file.

    Change the \"org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER\" setting to \"true\".

    EXAMPLE catalina.properties:
    ...
    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
    org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true
    ...

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-TCSV-00-000152'
  tag rid: 'SV-TCSV-00-000152'
  tag stig_id: 'TCSV-00-000152'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Check catalina.properties file
  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content)

  describe props do
    its(['org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER']) { should cmp 'true' }
  end
end
