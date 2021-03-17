# encoding: UTF-8

control 'VCLD-70-000006' do
  title "VAMI must produce log records containing sufficient information to
establish what type of events occurred."
  desc  "After a security incident has occurred, investigators will often
review log files to determine what happened.  Understanding what type of event
occurred is critical for investigation of a susipicous event.

  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep \"^accesslog.format\" /opt/vmware/etc/lighttpd/lighttpd.conf

    The default, commented, accesslog format is acceptable for this
requirement. No output should be returned.

    If the command returns any output, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

    Comment any existing accesslog.format lines by adding a '#' at the
beginning of the line.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000006'
  tag fix_id: nil
  tag cci: 'CCI-000130'
  tag nist: ['AU-3']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['accesslog.format'] do
    it { should eq nil }
  end

end

