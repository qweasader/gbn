# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883020");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2019-3804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-29 19:25:00 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"creation_date", value:"2019-03-21 09:50:36 +0100 (Thu, 21 Mar 2019)");
  script_name("CentOS Update for cockpit CESA-2019:0482 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0482");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-March/023221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cockpit'
  package(s) announced via the CESA-2019:0482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cockpit enables users to administer GNU/Linux servers using a web browser.
It offers network configuration, log inspection, diagnostic reports,
SELinux troubleshooting, interactive command-line sessions, and more.

Security Fix(es):

  * cockpit: Crash when parsing invalid base64 headers (CVE-2019-3804)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");

  script_tag(name:"affected", value:"cockpit on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if((res = isrpmvuln(pkg:"cockpit", rpm:"cockpit~173.2~1.el7.centos", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"cockpit-bridge", rpm:"cockpit-bridge~173.2~1.el7.centos", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"cockpit-doc", rpm:"cockpit-doc~173.2~1.el7.centos", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"cockpit-machines-ovirt", rpm:"cockpit-machines-ovirt~173.2~1.el7.centos", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"cockpit-system", rpm:"cockpit-system~173.2~1.el7.centos", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"cockpit-ws", rpm:"cockpit-ws~173.2~1.el7.centos", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if(__pkg_match) exit(99);
  exit(0);
}
