control 'HZNV-8X-000008' do
  title 'The Horizon Connection Server must require DoD PKI for administrative logins.'
  desc  "
    The Horizon Connection Server console supports CAC login as required for cryptographic non-repudiation. CAC login can be configured as disabled, optional, or required, but for maximum assurance it must be set to \"required\".

    In some circumstances, setting the CAC login as \"optional\" on the admin interface may be appropriate in order to support a \"break glass\" scenario where PKI is failing or connectivity issues occur. Requiring CAC login on the admin interface prevents login to the admin interface without a CAC - there is no means for setting a fallback method.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab. For each Connection Server listed, select the server and click \"Edit\".

    Click the \"Authentication\" tab and scroll down to \"Horizon Administrator Authentication\".

    Find the currently configured value in the drop down next to \"Smart card authentication for administrators\".

    If \"Smart card authentication for administrators\" is not set to \"Required\", this is a finding.

    Note: If another form of DoD approved PKI is used, and configured to be required for administrative logins, this is not a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab. For each Connection Server listed, select the server and click \"Edit\".

    Click the \"Authentication\" tab and scroll down to \"Horizon Administrator Authentication\".

    Ensure the value in the drop down next to \"Smart card authentication for administrators\" is set to \"Required\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag satisfies: ['SRG-APP-000149-AS-000102', 'SRG-APP-000151-AS-000103', 'SRG-APP-000153-AS-000104', 'SRG-APP-000177-AS-000126', 'SRG-APP-000391-AS-000239', 'SRG-APP-000392-AS-000240', 'SRG-APP-000403-AS-000248']
  tag gid: 'V-HZNV-8X-000008'
  tag rid: 'SV-HZNV-8X-000008'
  tag stig_id: 'HZNV-8X-000008'
  tag cci: ['CCI-000166', 'CCI-000187', 'CCI-000765', 'CCI-000767', 'CCI-000770', 'CCI-001953', 'CCI-001954', 'CCI-002010']
  tag nist: ['AU-10', 'IA-2 (1)', 'IA-2 (12)', 'IA-2 (3)', 'IA-2 (5)', 'IA-5 (2) (c)', 'IA-8 (1)']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')

  cslist = JSON.parse(result.stdout)

  cslist['value'].each do |cs|
    if cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] do
        subject { cs['authentication']['smartCardSupportForAdmin'] }
        it { should cmp 'ON' }
      end
    else
      describe 'CS not matched - ' + cs['general']['fqhn'] do
        skip 'CS fqdn not matched - ' + cs['general']['fqhn']
      end
    end
  end
end
