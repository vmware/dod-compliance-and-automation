control "ESXI-67-000040" do
  title "The ESXi host must use multifactor authentication for local DCUI
access to privileged accounts."
  desc  "To assure accountability and prevent unauthenticated access,
privileged users must utilize multifactor authentication to prevent potential
misuse and compromise of the system.

    Note: This feature requires an existing PKI and AD integration."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000107-VMM-000530"
  tag rid: "ESXI-67-000040"
  tag stig_id: "ESXI-67-000040"
  tag cci: "CCI-000767"
  tag nist: ["IA-2 (3)", "Rev_4"]

  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Authentication Services and view the Smart Card Authentication
status.

If \"Smart Card Mode\" is \"Disabled\", this is a finding.

For environments that do have PKI or AD available, this is not applicable."
  desc 'fix', "The following are pre-requisites to configuration smart card
authentication for the ESXi DCUI:
-Active Directory domain that supports smart card authentication, smart card
readers, and smart cards.
-ESXi joined to an Active Directory domain.
-Trusted certificates for root and intermediary certificate authorities.

From the vSphere Client select the ESXi Host and go to Configure >> System >>
Authentication Services and click Edit and check \"Enable Smart Card
Authentication\" checkbox, at the Certificates tab, click the green plus sign
to import trusted certificate authority certificates and click OK."

  describe "" do
    skip 'Manual verification is required for this control'
  end

end

