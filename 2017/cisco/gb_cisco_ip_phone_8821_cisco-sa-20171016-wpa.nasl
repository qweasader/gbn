# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140432");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-17 09:02:23 +0700 (Tue, 17 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Wireless IP Phone 8821 Multiple WPA2 Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ip_phone_detect.nasl");
  script_mandatory_keys("cisco/ip_phone/model");

  script_tag(name:"summary", value:"Cisco Wireless IP Phone 8821 is prone to key reinstallation attacks against
WPA protocol.");

  script_tag(name:"insight", value:"On October 16th, 2017, a research paper with the title of 'Key
Reinstallation Attacks: Forcing Nonce Reuse in WPA2' was made publicly available. This paper discusses seven
vulnerabilities affecting session key negotiation in both the Wi-Fi Protected Access (WPA) and the Wi-Fi Protected
Access II (WPA2) protocols. These vulnerabilities may allow the reinstallation of a pairwise transient key, a
group key, or an integrity key on either a wireless client or a wireless access point. Additional research also
led to the discovery of three additional vulnerabilities (not discussed in the original paper) affecting wireless
supplicant supporting either the 802.11z (Extensions to Direct-Link Setup) standard or the 802.11v (Wireless
Network Management) standard. The three additional vulnerabilities could also allow the reinstallation of a
pairwise key, group key, or integrity group key.");

  script_tag(name:"impact", value:"An attacker within the wireless communications range of an affected AP and
client may leverage packet decryption and injection, TCP connection hijacking, HTTP content injection, or the
replay of unicast, broadcast, and multicast frames.");

  script_tag(name:"solution", value:"Update to version 11.0(3)SR5 or later.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171016-wpa");

  exit(0);
}

include("version_func.inc");

if (!model = get_kb_item("cisco/ip_phone/model"))
  exit(0);

if (model =~ "^CP-8821") {
  if (!version = get_kb_item("cisco/ip_phone/version"))
    exit(0);

  version = eregmatch(pattern: "sip8821\.([0-9SR-]+)", string: version);

  if (!isnull(version[1])) {
    version = ereg_replace(string: version[1], pattern: "-", replace: ".");
    if (version_is_less(version: version, test_version: "11.0.3SR5")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.0.3SR5");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
