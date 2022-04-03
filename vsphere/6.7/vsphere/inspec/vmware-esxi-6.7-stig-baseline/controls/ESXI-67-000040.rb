control 'ESXI-67-000040' do
  title "The ESXi host must use multifactor authentication for local DCUI
access to privileged accounts."
  desc  "To ensure accountability and prevent unauthenticated access,
privileged users must utilize multifactor authentication to prevent potential
misuse and compromise of the system.

    Note: This feature requires an existing PKI and AD integration.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi Host and go to Configure >> System
>> Authentication Services and view the Smart Card Authentication status.

    If \"Smart Card Mode\" is \"Disabled\", this is a finding.

    For environments that do not have PKI or AD available, this is Not
Applicable.
  "
  desc  'fix', "
    The following are prerequisites to configuration of smart card
authentication for the ESXi DCUI:

    - Active Directory domain that supports smart card authentication, smart
card readers, and smart cards;
    - ESXi joined to an Active Directory domain; and
    - Trusted certificates for root and intermediary certificate authorities.

    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Authentication Services, click \"Edit\", and check the \"Enable Smart Card
Authentication\" checkbox.

    At the \"Certificates\" tab, click the green plus sign to import trusted
certificate authority certificates and click \"OK\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag satisfies: ['SRG-OS-000107-VMM-000530', 'SRG-OS-000376-VMM-001520',
'SRG-OS-000377-VMM-001530', 'SRG-OS-000403-VMM-001640']
  tag gid: 'V-239295'
  tag rid: 'SV-239295r816574_rule'
  tag stig_id: 'ESXI-67-000040'
  tag fix_id: 'F-42487r674813_fix'
  tag cci: ['CCI-000767', 'CCI-001953', 'CCI-001954', 'CCI-002470']
  tag nist: ['IA-2 (3)', 'IA-2 (12)', 'IA-2 (12)', 'SC-23 (5)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
