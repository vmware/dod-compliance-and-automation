include_controls 'photon' do
  # Syslog configuration is done in the VAMI
  skip_control 'PHTN-30-000039'
  # N/A to VCSA
  skip_control 'PHTN-30-000049'
  # NTP configuration is done in the VAMI
  skip_control 'PHTN-30-000058'
end
