include_controls 'photon' do
  # Syslog is addressed in the vCenter Application content and configured through the VAMI
  skip_control 'PHTN-30-000039'
  # NTP is addressed in the vCenter Application content and configured through the VAMI
  skip_control 'PHTN-30-000058'
  # VCSA currently cannot implement this control so it must be skipped.
  skip_control 'PHTN-30-000049'
end
