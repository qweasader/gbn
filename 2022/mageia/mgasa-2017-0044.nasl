# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0044");
  script_cve_id("CVE-2017-5208", "CVE-2017-5331", "CVE-2017-5332", "CVE-2017-5333");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 19:59:26 +0000 (Thu, 07 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0044)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0044");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0044.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/01/08/5");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/01/11/3");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20091");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3756");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icoutils' package(s) announced via the MGASA-2017-0044 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple programming errors in the wrestool tool of the icoutils suite
allows denial of service or the execution of arbitrary code if a malformed
binary is parsed (CVE-2017-5208, CVE-2017-5331, CVE-2017-5332,
CVE-2017-5333).");

  script_tag(name:"affected", value:"'icoutils' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"icoutils", rpm:"icoutils~0.31.1~1.mga5", rls:"MAGEIA5"))) {
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
