# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0162");
  script_cve_id("CVE-2018-1054");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 17:40:52 +0000 (Tue, 27 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0162");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0162.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/03/06/2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22710");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the MGASA-2018-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"389-ds-base has been updated to fix a security issue.

A flaw was found in 389 Directory Server that affects all versions. An
improper handling of the search feature with an extended filter, when
read access on <attribute_name> is enabled, in SetUnicodeStringFromUTF_8
function in collate.c, can lead to out-of-bounds memory operations. This
may allow a remote unauthenticated attacker to trigger a server crash,
thus resulting in denial of service. (CVE-2018-1054)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.5.17~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.5.17~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base-devel", rpm:"lib389-ds-base-devel~1.3.5.17~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base0", rpm:"lib389-ds-base0~1.3.5.17~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base-devel", rpm:"lib64389-ds-base-devel~1.3.5.17~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base0", rpm:"lib64389-ds-base0~1.3.5.17~1.3.mga6", rls:"MAGEIA6"))) {
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
