# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0256");
  script_cve_id("CVE-2014-0160");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0256");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0256.html");
  script_xref(name:"URL", value:"https://gitweb.torproject.org/tor.git?a=blob_plain;hb=HEAD;f=ChangeLog");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11922");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor' package(s) announced via the MGASA-2014-0256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 0.2.4.22 which solves these major and security problems:


 - Block authority signing keys that were used on authorities
 vulnerable to the 'heartbleed' bug in OpenSSL (CVE-2014-0160).

 - Fix a memory leak that could occur if a microdescriptor parse
 fails during the tokenizing step.

 - The relay ciphersuite list is now generated automatically based on
 uniform criteria, and includes all OpenSSL ciphersuites with
 acceptable strength and forward secrecy.

 - Relays now trust themselves to have a better view than clients of
 which TLS ciphersuites are better than others.

 - Clients now try to advertise the same list of ciphersuites as
 Firefox 28.


For other changes see the upstream change log");

  script_tag(name:"affected", value:"'tor' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.4.22~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.4.22~1.mga4", rls:"MAGEIA4"))) {
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
