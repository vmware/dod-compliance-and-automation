# encoding: UTF-8

control 'V-219157' do
  title "The Ubuntu operating system must not have the Network Information
Service (NIS) package installed."
  desc  "Removing the Network Information Service (NIS) package decreases the
risk of the accidental (or intentional) activation of NIS or NIS+ services."
  desc  'rationale', ''
  desc  'check', "
    Verify that the Network Information Service (NIS) package is not installed
on the Ubuntu operating system.

    Check to see if the NIS package is installed with the following command:

    # dpkg -l | grep nis

    If the NIS package is installed, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to disable non-essential capabilities
by removing the Network Information Service (NIS) package from the system with
the following command:

    # sudo apt-get remove nis
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-219157'
  tag rid: 'SV-219157r508662_rule'
  tag stig_id: 'UBTU-18-010018'
  tag fix_id: 'F-20881r304800_fix'
  tag cci: ['V-100539', 'SV-109643', 'CCI-000381']
  tag nist: ['CM-7 a']
  
  describe package('nis') do
    it { should_not be_installed }
  end
end

