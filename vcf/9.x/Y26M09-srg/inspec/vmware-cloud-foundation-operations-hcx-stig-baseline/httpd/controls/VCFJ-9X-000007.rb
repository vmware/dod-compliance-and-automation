control 'VCFJ-9X-000007' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.'
  desc  "
    Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

    The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the defined \"LogFormat\" includes sufficient information to aide in forensic investigation.

    At the command prompt, run the following:

    # grep -i \"LogFormat\" /etc/httpd/conf/httpd.conf /opt/vmware/config/apache-httpd/hcx-ssl.conf /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf

    Example output:

    LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b %{ms}T\" common

    Required elements:

     %h %l %u %t \\\"%r\\\" %>s %b

    If the value of \"LogFormat\" is defined and does not contain the required elements in any order, this is a finding.

    If \"LogFormat\" does not exist or is commented out, this is not a finding.

    Note: There can be multiple \"LogFormat\" settings defined.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Update the \"LogFormat\" definition to include the required elements, for example:

    LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b %{ms}T\" common

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag satisfies: ['SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000098-WSR-000060', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064', 'SRG-APP-000374-WSR-000172', 'SRG-APP-000375-WSR-000171']
  tag gid: 'V-VCFJ-9X-000007'
  tag rid: 'SV-VCFJ-9X-000007'
  tag stig_id: 'VCFJ-9X-000007'
  tag cci: ['CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000169', 'CCI-001487', 'CCI-001889', 'CCI-001890']
  tag nist: ['AU-12 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 f', 'AU-8 b']

  conf = input('apache_httpd_conf_file')
  apache_log_patterns = input('apache_log_patterns')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  logformats = apache_conf_custom(conf).LogFormat

  if !logformats.nil?
    logformats.each do |logformat|
      # Remove the garbage and create an array of elements in the log format
      logformatarray = logformat.gsub(/[\\\"]/, '').split
      # Remove the name of the log format from the array
      logformatname = logformatarray.pop
      apache_log_patterns.each do |pattern|
        describe "Logformat Name: #{logformatname} with pattern: #{logformatarray}" do
          subject { logformatarray }
          it { should include pattern }
        end
      end
    end
  else
    describe 'LogFormats' do
      subject { logformats }
      it { should be nil }
    end
  end
end
