# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0039");
  script_cve_id("CVE-2020-4051", "CVE-2021-23450");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-27 18:13:48 +0000 (Mon, 27 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2023-0039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0039");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0039.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31491");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-m8gw-hjpr-rjv7");
  script_xref(name:"URL", value:"https://github.com/dojo/dijit/security/advisories/GHSA-cxjc-r2fp-7mq6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dojo' package(s) announced via the MGASA-2023-0039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dijit Editor's LinkDialog plugin of dojo 1.14.0 to 1.14.7 is vulnerable to
cross-site scripting (XSS) attacks. (CVE-2020-4051)
Prototype pollution vulnerability via the setObject() function.
(CVE-2021-23450)");

  script_tag(name:"affected", value:"'dojo' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dojo", rpm:"dojo~1.16.5~1.mga8", rls:"MAGEIA8"))) {
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
