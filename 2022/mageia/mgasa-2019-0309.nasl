# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0309");
  script_cve_id("CVE-2019-10206", "CVE-2019-14846", "CVE-2019-14858");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-09 15:18:39 +0000 (Mon, 09 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0309");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0309.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:3203");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25607");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the MGASA-2019-0309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ansible package fixes security vulnerabilities:

ansible-playbook -k and ansible cli tools prompt passwords by expanding
them from templates as they could contain special characters. Passwords
should be wrapped to prevent templates trigger and exposing them
(CVE-2019-10206).

Ansible was logging at the DEBUG level which lead to a disclosure of
credentials if a plugin used a library that logged credentials at the
DEBUG level. This flaw does not affect Ansible modules, as those are
executed in a separate process (CVE-2019-14846).

When a module has an argument_spec with sub parameters marked as no_log,
passing an invalid parameter name to the module will cause the task to
fail before the no_log options in the sub parameters are processed. As a
result, data in the sub parameter fields will not be masked and will be
displayed if Ansible is run with increased verbosity and present in the
module invocation arguments for the task (CVE-2019-14858).");

  script_tag(name:"affected", value:"'ansible' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.7.14~1.mga7", rls:"MAGEIA7"))) {
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
