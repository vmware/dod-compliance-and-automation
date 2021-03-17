# encoding: UTF-8

control 'PHTN-30-000069' do
  title 'The Photon operating system must audit the insmod module.'
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep \"/sbin/insmod\"

    Expected result:

    -w /sbin/insmod -p x

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -w /sbin/insmod -p x

    At the command line, execute the following command to load the new audit
rules.

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag stig_id: 'PHTN-30-000069'
  tag cci: 'CCI-000172'
  tag nist: ['AU-12 c']

  describe auditd do
    its("lines") { should include %r{-w /sbin/insmod -p x} }
  end

end

