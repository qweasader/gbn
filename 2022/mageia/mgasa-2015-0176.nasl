# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0176");
  script_cve_id("CVE-2014-2977", "CVE-2014-2978");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0176");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0176.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-04/msg00060.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13391");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'directfb' package(s) announced via the MGASA-2015-0176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated directfb packages fix security vulnerabilities:

Multiple integer signedness errors in the Dispatch_Write function in
proxy/dispatcher/idirectfbsurface_dispatcher.c in DirectFB allow remote
attackers to cause a denial of service (crash) and possibly execute arbitrary
code via the Voodoo interface, which triggers a stack-based buffer overflow
(CVE-2014-2977).

The Dispatch_Write function in proxy/dispatcher/idirectfbsurface_dispatcher.c
in DirectFB allows remote attackers to cause a denial of service (crash) and
possibly execute arbitrary code via the Voodoo interface, which triggers an
out-of-bounds write (CVE-2014-2978).");

  script_tag(name:"affected", value:"'directfb' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"directfb", rpm:"directfb~1.7.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"directfb-doc", rpm:"directfb-doc~1.7.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64directfb-devel", rpm:"lib64directfb-devel~1.7.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64directfb1.7_0", rpm:"lib64directfb1.7_0~1.7.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdirectfb-devel", rpm:"libdirectfb-devel~1.7.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdirectfb1.7_0", rpm:"libdirectfb1.7_0~1.7.0~2.1.mga4", rls:"MAGEIA4"))) {
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
