# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0246");
  script_cve_id("CVE-2019-19232", "CVE-2019-19233", "CVE-2019-19234");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 16:15:00 +0000 (Thu, 30 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0246)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0246");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0246.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26314");
  script_xref(name:"URL", value:"https://www.sudo.ws/legacy.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IY6DZ7WMDKU4ZDML6MJLDAPG42B5WVUC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the MGASA-2020-0246 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated sudo packages fix security vulnerabilities:

It was found that sudo always allowed commands to be run with unknown
user or group ids if the sudo configuration allowed it for example via
the 'ALL' alias. This could allow sudo to impersonate non-existent
account and depending on how applications are configured, could lead to
certain restriction bypass. This is now explicitly disabled. A new
setting called 'allow_unknown_runas_id' was introduced in order to enable
this (CVE-2019-19232).

When an account is disabled via the shadow file, by replacing the
password hash with '!', it is not considered disabled by sudo. And
depending on the configuration, sudo can be run by using such disabled
account (CVE-2019-19234).

The sudo package has been updated to version 1.8.31p1, fixing these
issues and other bugs.");

  script_tag(name:"affected", value:"'sudo' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.31p1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.31p1~1.1.mga7", rls:"MAGEIA7"))) {
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
