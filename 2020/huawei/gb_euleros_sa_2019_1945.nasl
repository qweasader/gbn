# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1945");
  script_cve_id("CVE-2019-9494", "CVE-2019-9496");
  script_tag(name:"creation_date", value:"2020-01-23 12:28:13 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-15 22:29:00 +0000 (Wed, 15 May 2019)");

  script_name("Huawei EulerOS: Security Advisory for wpa_supplicant (EulerOS-SA-2019-1945)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1945");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1945");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'wpa_supplicant' package(s) announced via the EulerOS-SA-2019-1945 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The implementations of SAE in hostapd and wpa_supplicant are vulnerable to side channel attacks as a result of observable timing differences and cache access patterns. An attacker may be able to gain leaked information from a side channel attack that can be used for full password recovery. Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.7 are affected.(CVE-2019-9494)


An invalid authentication sequence could result in the hostapd process terminating due to missing state validation steps when processing the SAE confirm message when in hostapd/AP mode. All version of hostapd with SAE support are vulnerable. An attacker may force the hostapd process to terminate, performing a denial of service attack. Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.7 are affected.(CVE-2019-9496)");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.6~9.h6", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
