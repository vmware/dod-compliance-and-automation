# Change Log

## [8.14 Version 1 Release 4] (2024-02-21)

#### Release Notes
- Included Photon controls locally rather than linking to the Photon content.

- Cassandra:
  - Misc. tech edits for VLIC-8X-000006,007,013,014
  - VLIC-8X-000012,016 - Removed (Check and Fix duplicated in other control)

- Photon:
  - Misc. tech edits for PHTN-40-000003,007,019,031,035,036,037,038,041,042,043,046,
    047,067,068,076,078,086,105,107,160,173,175,184,185,187,193,196,200,204,206,213,
    214,215,216,223,224,225,226,227,228,229,231,232,238,244,246
  - PHTN-40-000121 - Removed (NTP handled by Application control)
     
- tc Server:
   - Renamed all controls (TCSV-00- to VRLT-8X-)
   - Replaced all $CATALINA_BASE and $CATALINA_HOME variables with actual paths
   - Added "VMware Aria Operations for Logs" product name to control titles
   - Misc. tech edits for VRLT-8X-000001,151,152
   - Removed the following controls (FIPS settings handled by Application controls):
     - TCSV-00-000002,100
   - Removed the following controls (service configuration handled by script):
     - TCSV-00-000037,045,048,051,088,106,134
   - Removed the following controls (auditing and updating handled by other controls):
   - TCSV-00-000105,117,147,148,149

## [8.14 Version 1 Release 3] (2023-12-22)

#### Release Notes
- Updated to include Photon 4.0 guidance


## [8.12 Version 1 Release 2] (2023-12-20)

#### Release Notes
- Rebranded and updated the following application controls:
  - VLIA-8X-000001
  - VLIA-8X-000002
  - VLIA-8X-000003
  - VLIA-8X-000004
  - VLIA-8X-000005
  - VLIA-8X-000006
  - VLIA-8X-000007
  - VLIA-8X-000008
  - VLIA-8X-000009
  - VLIA-8X-000010
  - VLIA-8X-000011
  - VLIA-8X-000012
  - VLIA-8X-000056

- Rebranded and updated the following cassandra controls:
  - VLIC-8X-000006
  - VLIC-8X-000007
  - VLIC-8X-000012
  - VLIC-8X-000013
  - VLIC-8X-000014
  - VLIC-8X-000016

- Removed the following cassandra controls:
  - VLIC-8X-000001
  - VLIC-8X-000002
  - VLIC-8X-000003
  - VLIC-8X-000004
  - VLIC-8X-000005
  - VLIC-8X-000008
  - VLIC-8X-000009
  - VLIC-8X-000010
  - VLIC-8X-000011
  - VLIC-8X-000015
  - VLIC-8X-000017
  - VLIC-8X-000130

- Replaced the Tomcat controls with the tc Server controls
	 
- Linked to the Photon 3.0 controls


## [8.2 Version 1 Release 1] (2021-06-24)

#### Release Notes
- Initial release