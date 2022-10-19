control 'HZNV-8X-000133' do
  title 'The Horizon Connection Server must backup its configuration daily.'
  desc  "
    Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.

    In order to ensure the server configuration can be validated or reconfigured in the event of a security related incident, the server configuration must be backed up on a daily basis.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Select the \"Backup\" tab.

    Validate that \"Automatic backup frequency\" is set to a least \"Every day\".

    If the Connection Server is not set to be backed up daily (or less), this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Select the \"Backup\" tab.

    Set \"Automatic backup frequency\" to \"Every day\" or select a more frequent option.

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000133'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')

  cslist = JSON.parse(result.stdout)

  cslist['value'].each do |cs|
    if cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] do
        subject { cs['backup']['ldapBackupFrequencyTime'] }
        it { should cmp input('backupFrequency') }
      end
    else
      describe 'CS not matched - ' + cs['general']['fqhn'] do
        skip 'CS fqdn not matched - ' + cs['general']['fqhn']
      end
    end
  end
end
