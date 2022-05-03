control 'VCLD-70-000023' do
  title 'VAMI must be protected from being stopped by a non-privileged user.'
  desc  "
    An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration. As such, only administrators should ever be able to stop VAMI.

    The VAMI process is configured out of the box to be owned by root. This configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ps -f -U root | awk '$0 ~ /vami-lighttpd/ && $0 !~ /awk/ {print $1}'

    Expected result:

    root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/systemd/system/vami-lighttp.service

    Under the \"[Service]\" section, remove the line that beings with \"User=\".

    Restart the service with the following command:

    # vmon-cli --restart applmgmt
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000023'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  describe command("ps -f -U root | awk '$0 ~ /vami-lighttpd/ && $0 !~ /awk/ {print $1}'") do
    its('stdout.strip') { should cmp 'root' }
  end
end
