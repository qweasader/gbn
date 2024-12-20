# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0258");
  script_cve_id("CVE-2018-20060", "CVE-2019-11236", "CVE-2019-11324");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-19 17:12:26 +0000 (Fri, 19 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0258");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0258.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23880");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3990-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-requests, python-urllib3' package(s) announced via the MGASA-2019-0258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that urllib3 incorrectly removed Authorization HTTP
headers when handled cross-origin redirects. This could result in
credentials being sent to unintended hosts (CVE-2018-20060).

It was discovered that urllib3 incorrectly stripped certain characters
from requests. A remote attacker could use this issue to perform CRLF
injection (CVE-2019-11236).

It was discovered that urllib3 incorrectly handled situations where a
desired set of CA certificates were specified. This could result in
certificates being accepted by the default CA certificates contrary to
expectations (CVE-2019-11324).

The python-urllib3 package has been updated to version 1.24.3 to fix these
issues and other bugs. The python-requests package has been fixed to work
with the updated python-urllib3");

  script_tag(name:"affected", value:"'python-requests, python-urllib3' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~2.11.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.24.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.11.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.24.3~1.mga6", rls:"MAGEIA6"))) {
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
