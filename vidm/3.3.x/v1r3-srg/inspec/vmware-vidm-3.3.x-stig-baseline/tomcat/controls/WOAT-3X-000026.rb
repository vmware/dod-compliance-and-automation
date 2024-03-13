control 'WOAT-3X-000026' do
  title 'The WS1Access webapps must not be modified from their shipping state.'
  desc  'VMware ships Workspace ONE Access ships with several tomcat webapps. The present web apps should be checked for webapps that did not ship with the appliance and therefore are potentially malicious and must be removed.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # ls -1 /opt/vmware/horizon/workspace/webapps

    Expected result:

    acs
    AUDIT
    catalog-portal
    cfg
    hc
    mtkadmin
    ROOT
    SAAS
    ws1-admin
    ws-admin

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    For each unexpected directory returned in the check, run the following command:

    # rm /opt/vmware/horizon/workspace/webapps/<NAME>

    Restart the service with the following command:

    # systemctl restart horizon-workspace
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: 'V-WOAT-3X-000026'
  tag rid: 'SV-WOAT-3X-000026'
  tag stig_id: 'WOAT-3X-000026'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  webappslist = %w(acs AUDIT catalog-portal cfg hc mtkadmin ROOT SAAS ws1-admin ws-admin)
  apps = command('ls -1 /opt/vmware/horizon/workspace/webapps').stdout.strip.split("\n")

  apps.each do |app|
    describe app do
      it { should be_in webappslist }
    end
  end
end
