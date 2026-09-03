control 'VCFH-9X-000008' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must initiate session logging upon start up.'
  desc  'An attacker can compromise a web server during the startup process. If logging is not initiated until all the web server processes are started, key information may be missed and not be available during a forensic investigation. To ensure all logable events are captured, the web server must begin logging once the first web server process is initiated.'
  desc  'rationale', ''
  desc  'check', "
    Verify the \"log_config_module\" is present.

    At the command prompt, run the following:

    # httpd -M | grep -i \"log_config_module\"

    Example output:

    log_config_module (shared)

    If the \"log_config_module\" is not found, this is a finding.

    Verify the \"CustomLog\" directive is defined.

    At the command prompt, run the following:

    # grep -i \"CustomLog\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Example output:

    CustomLog \"/var/log/apache2/access_log\" common

    If \"CustomLog\" is not present, this is a finding.

    If \"CustomLog\" does not use a \"LogFormat\" with the required elements, this is a finding.

    Note: The required elements are \"%h, %l, %u, %t, %r, %>s, and %b\", and are covered by control VCFH-9X-000007.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Add or update the \"CustomLog\" directive, for example:

    CustomLog \"/var/log/apache2/access_log\" common

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag satisfies: ['SRG-APP-000358-WSR-000063']
  tag gid: 'V-VCFH-9X-000008'
  tag rid: 'SV-VCFH-9X-000008'
  tag stig_id: 'VCFH-9X-000008'
  tag cci: ['CCI-001464', 'CCI-001851']
  tag nist: ['AU-14 (1)', 'AU-4 (1)']

  conf = input('apache_httpd_conf_file')
  vhconf = input('apache_virtualhost_conf_file')
  apache_log_patterns = input('apache_log_patterns')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(vhconf) do
    it { should exist }
  end

  # Build list of defined LogFormats that are compliant
  logformats = apache_conf_custom(conf).LogFormat
  goodlogformats = []

  if !logformats.nil?
    logformats.each do |logformat|
      # Remove the garbage and create an array of elements in the log format
      logformatarray = logformat.gsub(/[\\"]/, '').split
      # Remove the name of the log format from the array
      logformatname = logformatarray.pop

      # Add LogFormat name to list of compliant Logformats
      next unless apache_log_patterns.all? { |e| logformatarray.include?(e) }
      goodlogformats.push(logformatname)
    end
  else
    describe 'LogFormats' do
      subject { logformats }
      it { should_not be_nil }
    end
  end

  customlogs = apache_conf_custom(vhconf).CustomLog

  # Check each CustomLog directive and make sure it uses a compliant LogFormat
  # if !logformats.nil? && !customlogs.nil?
  if !customlogs.nil?
    customlogs.each do |customlog|
      describe.one do
        customlogarray = customlog.gsub(/[\\"]/, '').split

        apache_log_patterns.each do |item|
          describe customlogarray do
            it { should include item }
          end
        end

        # Does the customlog array include any of the good logformat names?
        result = goodlogformats.any? { |e| customlogarray.include?(e) }
        describe "CustomLog: #{customlogarray} should use a compliant LogFormat: #{goodlogformats}" do
          subject { result }
          it { should cmp true }
        end
      end
    end
  else
    describe 'CustomLog' do
      subject { customlogs }
      it { should_not be_nil }
    end
  end
end
