# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105549");
  script_cve_id("CVE-2015-7575");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - SLOTH: TLS 1.2 handshake vulnerability CVE-2015-7575");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K02201365");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way TLS 1.2 uses RSA+MD5 signatures with Client Authentication and ServerKeyExchange messages during a TLS 1.2 handshakes. An attacker with a Man-in-the-Middle network position and the ability to force / observe the use of RSA+MD5 during a TLS Handshake, may be able to successfully generate a hash collision and impersonate a TLS client or server. The vulnerability of CVE-2015-7575 is relevant to cryptography software which supports TLS 1.2 only as earlier versions of TLS used different hash functionality in those protocols.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-16 16:20:45 +0100 (Tue, 16 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_f5_big_ip_ssh_login_detect.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("f5.inc");
include("host_details.inc");
include("list_array_func.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "ssh-login"))
  exit(0);

check_f5["LTM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["AAM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.4.0-11.4.1;");

check_f5["AFM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.3.0-11.4.1;");

check_f5["AVR"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;");

check_f5["APM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["PEM"] = make_array("affected",   "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;",
                             "unaffected", "12.0.0-12.1.0;11.5.1_HF3-11.6.0;11.5.0_HF4-11.5.0_HF7;11.3.0-11.4.1;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
