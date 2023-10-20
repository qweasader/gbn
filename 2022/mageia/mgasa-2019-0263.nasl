# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0263");
  script_cve_id("CVE-2018-1000550");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 21:15:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0263");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0263.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23536");
  script_xref(name:"URL", value:"https://sympa-community.github.io/security/2018-001.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4285");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sympa' package(s) announced via the MGASA-2019-0263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated sympa packages fix security vulnerability:

Michael Kaczmarczik discovered a vulnerability in the web interface
template editing function of Sympa, a mailing list manager. Owner and
listmasters could use this flaw to create or modify arbitrary files in
the server with privileges of sympa user or owner view list config files
even if edit_list.conf prohibits it (CVE-2018-1000550).");

  script_tag(name:"affected", value:"'sympa' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"sympa", rpm:"sympa~6.2.16~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sympa-www", rpm:"sympa-www~6.2.16~1.1.mga6", rls:"MAGEIA6"))) {
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
