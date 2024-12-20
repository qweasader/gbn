# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0024");
  script_cve_id("CVE-2016-6251", "CVE-2016-6252");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-22 17:50:57 +0000 (Wed, 22 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0024");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0024.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/20/2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18984");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shadow-utils' package(s) announced via the MGASA-2017-0024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that shadow-utils-4.2.1 had a potentially unsafe use of
getlogin with the concern that the utmp entry might have a spoofed
username associated with a correct uid (CVE-2016-6251).

It was found that shadow-utils-4.2.1 had an incorrect integer handling
problem where it looks like the int wrap is exploitable as a LPE, as the
kernel is using 32bit uid's that are truncated from unsigned longs
(64bit on x64) as returned by simple_strtoul() [map_write()].
(CVE-2016-6252).");

  script_tag(name:"affected", value:"'shadow-utils' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"shadow-utils", rpm:"shadow-utils~4.2.1~6.mga5", rls:"MAGEIA5"))) {
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
