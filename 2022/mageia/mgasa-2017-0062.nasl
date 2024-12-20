# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0062");
  script_cve_id("CVE-2016-9577", "CVE-2016-9578");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-24 18:40:52 +0000 (Mon, 24 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0062");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0062.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20251");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2017-0254.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice' package(s) announced via the MGASA-2017-0062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated attacker could send crafted messages to the spice server
causing a heap overflow leading to a crash or possible code execution.
(CVE-2016-9577)

An attacker able to connect to the spice server could send crafted
messages which would cause the process to crash. (CVE-2016-9578)");

  script_tag(name:"affected", value:"'spice' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-server-devel", rpm:"lib64spice-server-devel~0.12.5~2.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-server1", rpm:"lib64spice-server1~0.12.5~2.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-server-devel", rpm:"libspice-server-devel~0.12.5~2.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-server1", rpm:"libspice-server1~0.12.5~2.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice", rpm:"spice~0.12.5~2.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice-client", rpm:"spice-client~0.12.5~2.4.mga5", rls:"MAGEIA5"))) {
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
