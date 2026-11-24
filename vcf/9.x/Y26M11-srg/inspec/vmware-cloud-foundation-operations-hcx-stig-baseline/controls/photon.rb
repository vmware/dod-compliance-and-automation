include_controls 'photon' do
  # rsyslog controls are currently N/A to HCX appliances as it currently uses syslog-ng instead.
  skip_control 'PHTN-50-000012'
  skip_control 'PHTN-50-000074'
  skip_control 'PHTN-50-000241'
  skip_control 'PHTN-50-000242'
end
