control 'VCFA-9X-000382' do
  title 'VMware Cloud Foundation Operations HCX must be configured to forward logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations HCX is not deployed, this is not applicable.

    From the VCF Operations HCX Administration interface, go to Administration >> General Settings >> Syslog Server.

    Review the primary and secondary syslog server configuration.

    If log forwarding is not configured to an authorized central log server, this is a finding.
  "
  desc 'fix', "
    Configuring a syslog server for VCF Operations HCX forwards logs for both the manager and any dataplane appliances.

    From the VCF Operations HCX Administration interface, go to Administration >> General Settings >> Syslog Server.

    Click \"Edit\".

    Enter an IP or FQDN for an authorized central log server, port, and select a protocol for the primary syslog server.

    Optionally enter a secondary syslog server and click \"Save\".

    Manager logs are forwarded immediately but a \"Force Sync\" must be performed for the changes to take effect on dataplane appliances.

    To perform a force sync, do the following:

    From the VCF Operations HCX interface, go to Infrastructure >> Interconnect >> Service Mesh.

    For each service mesh select \"View Appliances\".

    Select all appliances and click \"Force-Sync\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCFA-9X-000382'
  tag rid: 'SV-VCFA-9X-000382'
  tag stig_id: 'VCFA-9X-000382'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  if input('opshcx_deployed')
    describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
      skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations HCX is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations HCX is not deployed in the target environment. This control is N/A.'
    end
  end
end
