# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0001");
  script_cve_id("CVE-2014-9220");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0001");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0001.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/12/03/1");
  script_xref(name:"URL", value:"http://www.openvas.org/OVSA20141128.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14718");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvas-libraries, openvas-manager' package(s) announced via the MGASA-2015-0001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openvas-manager packages fixes security vulnerability:

It has been identified that OpenVAS Manager before 4.0.6 is vulnerable to sql
injections due to a improper handling of the timezone parameter in
modify_schedule OMP command. It has been identified that this vulnerability
may allow read-access via sql for authorized user account which have
permission to modify schedule objects (CVE-2014-9220).");

  script_tag(name:"affected", value:"'openvas-libraries, openvas-manager' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openvas-devel", rpm:"lib64openvas-devel~6.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openvas6", rpm:"lib64openvas6~6.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvas-devel", rpm:"libopenvas-devel~6.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvas6", rpm:"libopenvas6~6.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvas-libraries", rpm:"openvas-libraries~6.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvas-manager", rpm:"openvas-manager~4.0.6~1.mga4", rls:"MAGEIA4"))) {
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
