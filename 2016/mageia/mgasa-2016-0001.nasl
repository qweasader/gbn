# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131172");
  script_cve_id("CVE-2015-0855");
  script_tag(name:"creation_date", value:"2016-01-11 09:15:37 +0000 (Mon, 11 Jan 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-04 01:59:00 +0000 (Tue, 04 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0001");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0001.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17393");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/12/23/8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pitivi' package(s) announced via the MGASA-2016-0001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In pitivi before 0.95, double-clicking a file in the user's media library
with a specially-crafted path or filename allows for arbitrary code
execution with the permissions of the user running Pitivi (CVE-2015-0855).");

  script_tag(name:"affected", value:"'pitivi' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"pitivi", rpm:"pitivi~0.94~3.1.mga5", rls:"MAGEIA5"))) {
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
