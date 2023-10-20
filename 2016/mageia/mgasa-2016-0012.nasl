# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131177");
  script_cve_id("CVE-2015-7501");
  script_tag(name:"creation_date", value:"2016-01-14 05:28:50 +0000 (Thu, 14 Jan 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0012");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0012.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17227");
  script_xref(name:"URL", value:"https://blogs.apache.org/foundation/entry/apache_commons_statement_to_widespread");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-2522.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-collections' package(s) announced via the MGASA-2016-0012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the Apache commons-collections library permitted code
execution when deserializing objects involving a specially constructed
chain of classes. A remote attacker could use this flaw to execute
arbitrary code with the permissions of the application using the
commons-collections library (CVE-2015-7501).

With this update, deserialization of certain classes in the
commons-collections library is no longer allowed. Applications that
require those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to re-enable
their deserialization.");

  script_tag(name:"affected", value:"'apache-commons-collections' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-collections", rpm:"apache-commons-collections~3.2.1~24.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-collections-javadoc", rpm:"apache-commons-collections-javadoc~3.2.1~24.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-collections-testframework", rpm:"apache-commons-collections-testframework~3.2.1~24.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-collections-testframework-javadoc", rpm:"apache-commons-collections-testframework-javadoc~3.2.1~24.1.mga5", rls:"MAGEIA5"))) {
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
