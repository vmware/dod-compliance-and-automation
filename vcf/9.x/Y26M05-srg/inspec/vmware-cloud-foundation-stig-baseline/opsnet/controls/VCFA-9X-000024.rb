control 'VCFA-9X-000024' do
  title 'VMware Cloud Foundation Operations for Networks must enable the generation of audit records with sufficient information to support investigations.'
  desc  "
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

    Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

    DOD has defined the list of events for which the application will provide an audit record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination actions.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Networks is not deployed, this is not applicable.

    From VCF Operations for Networks, go to Settings >> Logs >> Audit Logs.

    Review the \"Allow collection of Personally Identifiable Information\" setting.

    If the \"Allow collection of Personally Identifiable Information\" setting is not enabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Networks, go to Settings >> Logs >> Audit Logs.

    Click the radio button next to \"Allow collection of Personally Identifiable Information\" then click \"Save\" in the \"Confirm Action\" dialog.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089'
  tag gid: 'V-VCFA-9X-000024'
  tag rid: 'SV-VCFA-9X-000024'
  tag stig_id: 'VCFA-9X-000024'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  if input('opsnet_deployed')
    describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
      skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.'
    end
  end
end
