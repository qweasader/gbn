# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0114");
  script_cve_id("CVE-2014-1695");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0114)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0114");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0114.html");
  script_xref(name:"URL", value:"http://www.otrs.com/release-notes-otrs-help-desk-3-2-15/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12910");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-03-xss-issue/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'otrs' package(s) announced via the MGASA-2014-0114 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An attacker could send a specially prepared HTML email to OTRS. If he can
then trick an agent into following a special link to display this email,
JavaScript code would be executed (CVE-2014-1695).");

  script_tag(name:"affected", value:"'otrs' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.2.15~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.2.15~1.mga4", rls:"MAGEIA4"))) {
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
