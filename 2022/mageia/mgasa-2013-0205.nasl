# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0205");
  script_cve_id("CVE-2013-2119");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0205)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0205");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0205.html");
  script_xref(name:"URL", value:"http://blog.phusion.nl/2013/05/29/phusion-passenger-3-0-21-released/");
  script_xref(name:"URL", value:"http://blog.phusion.nl/2013/05/29/phusion-passenger-4-0-5-released/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108443.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10728");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10497");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-passenger' package(s) announced via the MGASA-2013-0205 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Phusion Passengers code did not always create temporary files and directories
in a secure manner. Temporary files and directories were sometimes created
with a predictable filename. A local attacker can pre-create temporary files,
resulting in a denial of service. In addition, this vulnerability allows a
local attacker to run arbitrary code as another user, by hijacking temporary
files (CVE-2013-2119).

The rubygem-passenger package has been upgraded to version 3.0.21, which fixes
this issue, as well as many others although at the moment has further issues
which will be fixed with another update (mga#10728).");

  script_tag(name:"affected", value:"'rubygem-passenger' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-passenger", rpm:"rubygem-passenger~3.0.21~2.mga3", rls:"MAGEIA3"))) {
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
