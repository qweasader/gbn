# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2336");
  script_cve_id("CVE-2019-6470");
  script_tag(name:"creation_date", value:"2020-01-23 12:47:29 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-06 21:52:25 +0000 (Wed, 06 Nov 2019)");

  script_name("Huawei EulerOS: Security Advisory for dhcp (EulerOS-SA-2019-2336)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.3\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2336");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2336");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'dhcp' package(s) announced via the EulerOS-SA-2019-2336 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There had existed in one of the ISC BIND libraries a bug in a function that was used by dhcpd when operating in DHCPv6 mode. There was also a bug in dhcpd relating to the use of this function per its documentation, but the bug in the library function prevented this from causing any harm. All releases of dhcpd from ISC contain copies of this, and other, BIND libraries in combinations that have been tested prior to release and are known to not present issues like this. Some third-party packagers of ISC software have modified the dhcpd source, BIND source, or version matchup in ways that create the crash potential. Based on reports available to ISC, the crash probability is large and no analysis has been done on how, or even if, the probability can be manipulated by an attacker. Affects: Builds of dhcpd versions prior to version 4.4.1 when using BIND versions 9.11.2 or later, or BIND versions with specific bug fixes backported to them. ISC does not have access to comprehensive version lists for all repackagings of dhcpd that are vulnerable. In particular, builds from other vendors may also be affected. Operators are advised to consult their vendor documentation.(CVE-2019-6470)");

  script_tag(name:"affected", value:"'dhcp' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.3.0.");

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

if(release == "EULEROSVIRTARM64-3.0.3.0") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.3.6~28.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~4.3.6~28.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-libs", rpm:"dhcp-libs~4.3.6~28.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.3.6~28.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.3.6~28.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
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
