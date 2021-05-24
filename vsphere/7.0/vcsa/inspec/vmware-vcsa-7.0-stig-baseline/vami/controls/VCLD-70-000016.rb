# encoding: UTF-8

control 'VCLD-70-000016' do
  title "VAMI must prevent hosted applications from exhausting system
resources."
  desc  "Most of the attention to denial-of-service (DoS) attacks focuses on
ensuring that systems and applications are not victims of these attacks.
However, these systems and applications must also be secured against use to
launch such an attack against others.

    A variety of technologies exist to limit or, in some cases, eliminate the
effects of DoS attacks. Limiting system resources that are allocated to any
user to a bare minimum may also reduce the ability of users to launch some DoS
attacks.

    One DoS mitigation is to prevent VAMI from keeping idle connections open
for too long.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep
\"server.max-keep-alive-idle\"|sed 's: ::g'

    Expected result:

    server.max-keep-alive-idle=30

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf file.

    Add or reconfigure the following value:

    server.max-keep-alive-idle = 30
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000016'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['server.max-keep-alive-idle'] do
    it { should cmp "#{input('maxKeepAliveIdle')}" }
  end

end

